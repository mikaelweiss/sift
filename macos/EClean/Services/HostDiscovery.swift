import Foundation
import Observation

@MainActor
@Observable
final class HostDiscovery {
    var hosts: [DiscoveredHost] = []
    var sshKeys: [SSHKeyFile] = []
    var isScanning = false

    private var bonjourResolver: BonjourSSHScanner?
    private var bonjourHosts: [DiscoveredHost] = []
    private var tailscaleHosts: [DiscoveredHost] = []

    func startDiscovery() {
        isScanning = true
        sshKeys = Self.scanSSHKeys()
        rebuildHostList()
        startBonjour()
        Task {
            let peers = await Self.discoverTailscalePeers()
            self.tailscaleHosts = peers
            self.rebuildHostList()
            self.isScanning = false
        }
    }

    func stopDiscovery() {
        bonjourResolver?.stop()
        bonjourResolver = nil
    }

    private func rebuildHostList() {
        let localName = Host.current().localizedName ?? "This Mac"
        let local = DiscoveredHost(name: "\(localName) (This Mac)", address: "127.0.0.1", source: .local, osHint: "macOS")
        var combined: [DiscoveredHost] = [local]
        combined.append(contentsOf: tailscaleHosts)
        combined.append(contentsOf: bonjourHosts)
        hosts = combined
    }

    private func startBonjour() {
        bonjourResolver?.stop()
        let scanner = BonjourSSHScanner { [weak self] found in
            Task { @MainActor [weak self] in
                self?.bonjourHosts = found
                self?.rebuildHostList()
            }
        }
        scanner.start()
        bonjourResolver = scanner
    }

    static func scanSSHKeys() -> [SSHKeyFile] {
        let sshDir = FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent(".ssh")
        guard let entries = try? FileManager.default.contentsOfDirectory(at: sshDir, includingPropertiesForKeys: [.isRegularFileKey]) else {
            return []
        }
        let ignored: Set<String> = ["known_hosts", "known_hosts.old", "authorized_keys", "config"]
        var keys: [SSHKeyFile] = []
        for url in entries {
            let name = url.lastPathComponent
            if name.hasSuffix(".pub") || ignored.contains(name) || name.hasPrefix(".") {
                continue
            }
            if let handle = try? FileHandle(forReadingFrom: url),
               let head = try? handle.read(upToCount: 40),
               let prefix = String(data: head, encoding: .utf8),
               prefix.contains("PRIVATE KEY") {
                keys.append(SSHKeyFile(name: name, path: url.path))
            }
        }
        return keys.sorted { $0.name < $1.name }
    }

    private static func discoverTailscalePeers() async -> [DiscoveredHost] {
        await Task.detached {
            let candidates = [
                "/usr/local/bin/tailscale",
                "/opt/homebrew/bin/tailscale",
                "/run/current-system/sw/bin/tailscale",
                "/Applications/Tailscale.app/Contents/MacOS/Tailscale",
            ]
            guard let binary = candidates.first(where: { FileManager.default.isExecutableFile(atPath: $0) }) else {
                return []
            }
            let proc = Process()
            proc.executableURL = URL(fileURLWithPath: binary)
            proc.arguments = ["status", "--json"]
            let outPipe = Pipe()
            let errPipe = Pipe()
            proc.standardOutput = outPipe
            proc.standardError = errPipe
            do {
                try proc.run()
                // Drain stdout before waitUntilExit to avoid deadlocking when status JSON exceeds the 64KB pipe buffer.
                let group = DispatchGroup()
                var outData = Data()
                group.enter()
                DispatchQueue.global(qos: .userInitiated).async {
                    outData = outPipe.fileHandleForReading.readDataToEndOfFile()
                    group.leave()
                }
                group.enter()
                DispatchQueue.global(qos: .userInitiated).async {
                    _ = errPipe.fileHandleForReading.readDataToEndOfFile()
                    group.leave()
                }
                group.wait()
                proc.waitUntilExit()
                guard proc.terminationStatus == 0 else { return [] }
                return parseTailscaleStatusJSON(outData)
            } catch {
                return []
            }
        }.value
    }

    nonisolated private static func parseTailscaleStatusJSON(_ data: Data) -> [DiscoveredHost] {
        struct TSStatus: Decodable {
            struct Peer: Decodable {
                let HostName: String?
                let DNSName: String?
                let OS: String?
                let TailscaleIPs: [String]?
                let Online: Bool?
            }
            let Peer: [String: Peer]?
        }
        guard let decoded = try? JSONDecoder().decode(TSStatus.self, from: data),
              let peers = decoded.Peer else {
            return []
        }
        var results: [DiscoveredHost] = []
        for peer in peers.values {
            guard peer.Online == true else { continue }
            let dns = (peer.DNSName ?? "").trimmingCharacters(in: CharacterSet(charactersIn: "."))
            let address = !dns.isEmpty ? dns : (peer.TailscaleIPs?.first ?? "")
            guard !address.isEmpty else { continue }
            let displayName = peer.HostName?.isEmpty == false ? peer.HostName! : address
            results.append(DiscoveredHost(name: displayName, address: address, source: .tailscale, osHint: peer.OS))
        }
        return results.sorted { $0.name.localizedCaseInsensitiveCompare($1.name) == .orderedAscending }
    }
}

private final class BonjourSSHScanner: NSObject, NetServiceBrowserDelegate, NetServiceDelegate {
    private let browser = NetServiceBrowser()
    private var services: [NetService] = []
    private var resolvedByName: [String: DiscoveredHost] = [:]
    private let onChange: ([DiscoveredHost]) -> Void

    init(onChange: @escaping ([DiscoveredHost]) -> Void) {
        self.onChange = onChange
        super.init()
        browser.delegate = self
    }

    func start() {
        browser.searchForServices(ofType: "_ssh._tcp.", inDomain: "local.")
    }

    func stop() {
        browser.stop()
        for svc in services {
            svc.stop()
        }
        services.removeAll()
    }

    func netServiceBrowser(_ browser: NetServiceBrowser, didFind service: NetService, moreComing: Bool) {
        service.delegate = self
        services.append(service)
        service.resolve(withTimeout: 5.0)
    }

    func netServiceBrowser(_ browser: NetServiceBrowser, didRemove service: NetService, moreComing: Bool) {
        services.removeAll { $0 == service }
        resolvedByName.removeValue(forKey: service.name)
        publish()
    }

    func netServiceDidResolveAddress(_ sender: NetService) {
        guard let rawHost = sender.hostName?.trimmingCharacters(in: CharacterSet(charactersIn: ".")),
              !rawHost.isEmpty else {
            return
        }
        resolvedByName[sender.name] = DiscoveredHost(
            name: sender.name,
            address: rawHost,
            source: .bonjour,
            osHint: nil
        )
        publish()
    }

    private func publish() {
        let sorted = resolvedByName.values.sorted {
            $0.name.localizedCaseInsensitiveCompare($1.name) == .orderedAscending
        }
        onChange(sorted)
    }
}
