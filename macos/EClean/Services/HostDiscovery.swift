import Foundation
import Network
import Observation

@MainActor
@Observable
final class HostDiscovery {
    var hosts: [DiscoveredHost] = []
    var sshKeys: [SSHKeyFile] = []
    var isScanning = false

    private var browser: NWBrowser?
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
        browser?.cancel()
        browser = nil
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
        browser?.cancel()
        let params = NWParameters()
        params.includePeerToPeer = true
        let newBrowser = NWBrowser(for: .bonjour(type: "_ssh._tcp", domain: nil), using: params)
        newBrowser.browseResultsChangedHandler = { [weak self] results, _ in
            var found: [DiscoveredHost] = []
            for result in results {
                if case let .service(name, _, domain, _) = result.endpoint {
                    let hostAddress = domain == "local." ? "\(name).local" : "\(name).\(domain)"
                    found.append(DiscoveredHost(name: name, address: hostAddress, source: .bonjour, osHint: nil))
                }
            }
            Task { @MainActor [weak self] in
                self?.bonjourHosts = found.sorted { $0.name.localizedCaseInsensitiveCompare($1.name) == .orderedAscending }
                self?.rebuildHostList()
            }
        }
        newBrowser.start(queue: DispatchQueue(label: "com.eclean.bonjour"))
        browser = newBrowser
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
                "/Applications/Tailscale.app/Contents/MacOS/Tailscale",
                "/opt/homebrew/bin/tailscale",
                "/usr/local/bin/tailscale",
                "/run/current-system/sw/bin/tailscale",
            ]
            guard let binary = candidates.first(where: { FileManager.default.isExecutableFile(atPath: $0) }) else {
                return []
            }
            let proc = Process()
            proc.executableURL = URL(fileURLWithPath: binary)
            proc.arguments = ["status", "--json"]
            let pipe = Pipe()
            proc.standardOutput = pipe
            proc.standardError = Pipe()
            do {
                try proc.run()
                proc.waitUntilExit()
                guard proc.terminationStatus == 0 else { return [] }
                let data = pipe.fileHandleForReading.readDataToEndOfFile()
                return parseTailscaleStatusJSON(data)
            } catch {
                return []
            }
        }.value
    }

    private static func parseTailscaleStatusJSON(_ data: Data) -> [DiscoveredHost] {
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
