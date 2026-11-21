import Foundation

struct RemoteHostInfo: Sendable {
    var os: String
    var arch: String
    var alreadyInstalled: Bool
    var existingPort: Int
    var existingFingerprint: String?
    var existingPairedDevices: Int
}

struct DeployTarget: Sendable {
    var isLocal: Bool
    var host: String
    var sshUser: String
    var sshKeyPath: String?
    var port: Int = 8443
}

struct DeployResult: Sendable {
    var host: String
    var port: Int
    var tlsFingerprint: String
    var pairingCode: String?
}

enum DeployError: LocalizedError {
    case commandFailed(String)
    case missingBinary(String)
    case invalidServerStatus(String)

    var errorDescription: String? {
        switch self {
        case .commandFailed(let msg): return msg
        case .missingBinary(let name): return "Bundled server binary \(name) not found inside app bundle."
        case .invalidServerStatus(let msg): return "Could not read server status: \(msg)"
        }
    }
}

enum SSHDeployer {
    static func bundledBinaryURL(os: String, arch: String) -> URL? {
        let name = "sift-\(os)-\(arch)"
        if let url = Bundle.main.resourceURL?.appendingPathComponent("Binaries/\(name)"),
           FileManager.default.fileExists(atPath: url.path) {
            return url
        }
        return nil
    }

    static func inspectHost(target: DeployTarget) async throws -> RemoteHostInfo {
        if target.isLocal {
            let arch = currentLocalArch()
            let localBin = localBinaryPath()
            if FileManager.default.isExecutableFile(atPath: localBin) {
                if let status = try? await runLocal(executable: localBin, args: ["status"]),
                   let parsed = parseStatusOutput(status) {
                    return RemoteHostInfo(
                        os: "darwin",
                        arch: arch,
                        alreadyInstalled: true,
                        existingPort: parsed.port,
                        existingFingerprint: parsed.fingerprint,
                        existingPairedDevices: parsed.pairedDevices
                    )
                }
            }
            return RemoteHostInfo(os: "darwin", arch: arch, alreadyInstalled: false, existingPort: target.port, existingFingerprint: nil, existingPairedDevices: 0)
        }

        let probeCmd = "uname -s; uname -m; if [ -x \"$HOME/.local/bin/sift\" ]; then \"$HOME/.local/bin/sift\" status 2>/dev/null || true; fi"
        let out = try await runSSH(target: target, command: probeCmd)
        let lines = out.components(separatedBy: .newlines).map { $0.trimmingCharacters(in: .whitespaces) }
        guard lines.count >= 2 else {
            throw DeployError.commandFailed("Unexpected remote probe output")
        }
        let os = normalizeOS(lines[0])
        let arch = normalizeArch(lines[1])

        let jsonStart = out.firstIndex(of: "{")
        if let jsonStart {
            let jsonSlice = String(out[jsonStart...])
            if let parsed = parseStatusOutput(jsonSlice), let fp = parsed.fingerprint, !fp.isEmpty {
                return RemoteHostInfo(
                    os: os,
                    arch: arch,
                    alreadyInstalled: true,
                    existingPort: parsed.port,
                    existingFingerprint: fp,
                    existingPairedDevices: parsed.pairedDevices
                )
            }
        }
        return RemoteHostInfo(os: os, arch: arch, alreadyInstalled: false, existingPort: target.port, existingFingerprint: nil, existingPairedDevices: 0)
    }

    static func deployOrUpdate(
        target: DeployTarget,
        isUpdate: Bool,
        progress: @escaping @Sendable (String) -> Void
    ) async throws -> DeployResult {
        if target.isLocal {
            return try await deployLocal(target: target, isUpdate: isUpdate, progress: progress)
        }
        return try await deployRemote(target: target, isUpdate: isUpdate, progress: progress)
    }

    private static func deployLocal(
        target: DeployTarget,
        isUpdate: Bool,
        progress: @escaping @Sendable (String) -> Void
    ) async throws -> DeployResult {
        let arch = currentLocalArch()
        guard let srcURL = bundledBinaryURL(os: "darwin", arch: arch) else {
            throw DeployError.missingBinary("sift-darwin-\(arch)")
        }

        progress("Installing sift binary on this Mac...")
        let dstPath = localBinaryPath()
        let dstURL = URL(fileURLWithPath: dstPath)
        try FileManager.default.createDirectory(at: dstURL.deletingLastPathComponent(), withIntermediateDirectories: true)
        let tmpURL = dstURL.appendingPathExtension("new")
        try? FileManager.default.removeItem(at: tmpURL)
        try FileManager.default.copyItem(at: srcURL, to: tmpURL)
        try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: tmpURL.path)
        _ = try FileManager.default.replaceItemAt(dstURL, withItemAt: tmpURL)

        progress("Configuring launchd background agent...")
        let agentsDir = FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent("Library/LaunchAgents")
        try FileManager.default.createDirectory(at: agentsDir, withIntermediateDirectories: true)
        let plistURL = agentsDir.appendingPathComponent("org.weisssolutions.sift.server.plist")
        let logDir = FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent("Library/Logs/sift")
        try FileManager.default.createDirectory(at: logDir, withIntermediateDirectories: true)

        let plistContent = launchAgentPlist(binaryPath: dstPath, port: target.port, logDir: logDir.path)
        try plistContent.write(to: plistURL, atomically: true, encoding: .utf8)

        progress("Starting sift server...")
        let uid = String(getuid())
        _ = try? await runLocal(executable: "/bin/launchctl", args: ["bootout", "gui/\(uid)/org.weisssolutions.sift.server"])
        _ = try await runLocal(executable: "/bin/launchctl", args: ["bootstrap", "gui/\(uid)", plistURL.path])

        progress("Waiting for TLS certificate and health...")
        let status = try await waitForLocalStatus(binaryPath: dstPath)
        guard let fp = status.fingerprint, !fp.isEmpty else {
            throw DeployError.invalidServerStatus("TLS fingerprint missing")
        }

        var code: String? = nil
        if !isUpdate && status.pairedDevices == 0 {
            let pairOut = try await runLocal(executable: dstPath, args: ["pair"])
            code = extractSixDigitCode(from: pairOut)
        }
        return DeployResult(host: "127.0.0.1", port: status.port, tlsFingerprint: fp, pairingCode: code)
    }

    private static func deployRemote(
        target: DeployTarget,
        isUpdate: Bool,
        progress: @escaping @Sendable (String) -> Void
    ) async throws -> DeployResult {
        progress("Detecting remote OS and architecture...")
        let info = try await inspectHost(target: target)
        guard let srcURL = bundledBinaryURL(os: info.os, arch: info.arch) else {
            throw DeployError.missingBinary("sift-\(info.os)-\(info.arch)")
        }

        progress("Uploading sift (\(info.os)/\(info.arch)) over SSH...")
        _ = try await runSSH(target: target, command: "mkdir -p \"$HOME/.local/bin\"")
        try await runSCP(target: target, localPath: srcURL.path, remotePath: ".local/bin/sift.new")
        _ = try await runSSH(target: target, command: "chmod +x \"$HOME/.local/bin/sift.new\" && mv -f \"$HOME/.local/bin/sift.new\" \"$HOME/.local/bin/sift\"")

        progress("Configuring background service...")
        if info.os == "linux" {
            let unitCmd = """
            mkdir -p "$HOME/.config/systemd/user"
            cat > "$HOME/.config/systemd/user/sift.service" <<'EOF'
            [Unit]
            Description=Sift Spam Filter Daemon
            After=network-online.target

            [Service]
            ExecStart=%h/.local/bin/sift serve --port \(target.port)
            Restart=always
            RestartSec=5

            [Install]
            WantedBy=default.target
            EOF
            systemctl --user daemon-reload
            systemctl --user enable sift.service
            systemctl --user restart sift.service
            loginctl enable-linger "$USER" 2>/dev/null || true
            """
            _ = try await runSSH(target: target, command: unitCmd)
        } else {
            let plistCmd = """
            xattr -d com.apple.quarantine "$HOME/.local/bin/sift" 2>/dev/null || true
            mkdir -p "$HOME/Library/LaunchAgents" "$HOME/Library/Logs/sift"
            cat > "$HOME/Library/LaunchAgents/org.weisssolutions.sift.server.plist" <<EOF
            \(launchAgentPlist(binaryPath: "$HOME/.local/bin/sift", port: target.port, logDir: "$HOME/Library/Logs/sift"))
            EOF
            UID_NUM="$(id -u)"
            launchctl bootout "gui/$UID_NUM/org.weisssolutions.sift.server" 2>/dev/null || true
            launchctl bootout "user/$UID_NUM/org.weisssolutions.sift.server" 2>/dev/null || true
            if ! launchctl bootstrap "gui/$UID_NUM" "$HOME/Library/LaunchAgents/org.weisssolutions.sift.server.plist" 2>/dev/null; then
              if ! launchctl bootstrap "user/$UID_NUM" "$HOME/Library/LaunchAgents/org.weisssolutions.sift.server.plist" 2>/dev/null; then
                pkill -f "$HOME/.local/bin/sift serve" 2>/dev/null || true
                nohup "$HOME/.local/bin/sift" serve --port \(target.port) >"$HOME/Library/Logs/sift/stdout.log" 2>"$HOME/Library/Logs/sift/stderr.log" </dev/null &
              fi
            fi
            """
            _ = try await runSSH(target: target, command: plistCmd)
        }

        progress("Verifying server startup...")
        let status = try await waitForRemoteStatus(target: target)
        guard let fp = status.fingerprint, !fp.isEmpty else {
            throw DeployError.invalidServerStatus("TLS fingerprint missing after startup")
        }

        var code: String? = nil
        if !isUpdate && status.pairedDevices == 0 {
            let pairOut = try await runSSH(target: target, command: "\"$HOME/.local/bin/sift\" pair")
            code = extractSixDigitCode(from: pairOut)
        }
        return DeployResult(host: target.host, port: status.port, tlsFingerprint: fp, pairingCode: code)
    }

    private static func waitForLocalStatus(binaryPath: String) async throws -> ParsedStatus {
        for _ in 0..<15 {
            if let out = try? await runLocal(executable: binaryPath, args: ["status"]),
               let parsed = parseStatusOutput(out),
               let fp = parsed.fingerprint, !fp.isEmpty {
                return parsed
            }
            try await Task.sleep(nanoseconds: 500_000_000)
        }
        throw DeployError.invalidServerStatus("Timed out waiting for local server TLS fingerprint")
    }

    private static func waitForRemoteStatus(target: DeployTarget) async throws -> ParsedStatus {
        for _ in 0..<15 {
            if let out = try? await runSSH(target: target, command: "\"$HOME/.local/bin/sift\" status"),
               let parsed = parseStatusOutput(out),
               let fp = parsed.fingerprint, !fp.isEmpty {
                return parsed
            }
            try await Task.sleep(nanoseconds: 600_000_000)
        }
        throw DeployError.invalidServerStatus("Timed out waiting for remote server TLS fingerprint")
    }

    private struct ParsedStatus {
        var port: Int
        var fingerprint: String?
        var pairedDevices: Int
    }

    private static func parseStatusOutput(_ text: String) -> ParsedStatus? {
        guard let data = text.data(using: .utf8),
              let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            return nil
        }
        let portStr = obj["listen_port"] as? String ?? "8443"
        let port = Int(portStr) ?? 8443
        let fp = obj["tls_fingerprint"] as? String
        let paired = obj["paired_devices"] as? Int ?? 0
        return ParsedStatus(port: port, fingerprint: fp, pairedDevices: paired)
    }

    private static func extractSixDigitCode(from text: String) -> String? {
        let pattern = #"\b\d{6}\b"#
        guard let regex = try? NSRegularExpression(pattern: pattern),
              let match = regex.firstMatch(in: text, range: NSRange(text.startIndex..., in: text)),
              let range = Range(match.range, in: text) else {
            return nil
        }
        return String(text[range])
    }

    private static func runSSH(target: DeployTarget, command: String) async throws -> String {
        var args = ["-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=accept-new", "-o", "ConnectTimeout=10"]
        if let key = target.sshKeyPath, !key.isEmpty {
            args.append(contentsOf: ["-i", key])
        }
        let dest = target.sshUser.isEmpty ? target.host : "\(target.sshUser)@\(target.host)"
        args.append(dest)
        args.append(command)
        return try await runLocal(executable: "/usr/bin/ssh", args: args)
    }

    private static func runSCP(target: DeployTarget, localPath: String, remotePath: String) async throws {
        var args = ["-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=accept-new", "-o", "ConnectTimeout=10"]
        if let key = target.sshKeyPath, !key.isEmpty {
            args.append(contentsOf: ["-i", key])
        }
        let dest = target.sshUser.isEmpty ? target.host : "\(target.sshUser)@\(target.host)"
        args.append(localPath)
        args.append("\(dest):\(remotePath)")
        _ = try await runLocal(executable: "/usr/bin/scp", args: args)
    }

    private static func runLocal(executable: String, args: [String]) async throws -> String {
        try await Task.detached {
            let proc = Process()
            proc.executableURL = URL(fileURLWithPath: executable)
            proc.arguments = args
            let outPipe = Pipe()
            let errPipe = Pipe()
            proc.standardOutput = outPipe
            proc.standardError = errPipe
            try proc.run()
            let group = DispatchGroup()
            var outData = Data()
            var errData = Data()
            group.enter()
            DispatchQueue.global(qos: .userInitiated).async {
                outData = outPipe.fileHandleForReading.readDataToEndOfFile()
                group.leave()
            }
            group.enter()
            DispatchQueue.global(qos: .userInitiated).async {
                errData = errPipe.fileHandleForReading.readDataToEndOfFile()
                group.leave()
            }
            group.wait()
            proc.waitUntilExit()
            let outStr = String(data: outData, encoding: .utf8) ?? ""
            let errStr = String(data: errData, encoding: .utf8) ?? ""
            if proc.terminationStatus != 0 {
                let msg = errStr.trimmingCharacters(in: .whitespacesAndNewlines)
                throw DeployError.commandFailed(msg.isEmpty ? "Command exited with status \(proc.terminationStatus)" : msg)
            }
            return outStr
        }.value
    }

    private static func localBinaryPath() -> String {
        FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent("Library/Application Support/sift/bin/sift")
            .path
    }

    private static func currentLocalArch() -> String {
        #if arch(arm64)
        return "arm64"
        #else
        return "amd64"
        #endif
    }

    private static func normalizeOS(_ raw: String) -> String {
        switch raw.lowercased() {
        case "darwin": return "darwin"
        default: return "linux"
        }
    }

    private static func normalizeArch(_ raw: String) -> String {
        switch raw.lowercased() {
        case "arm64", "aarch64": return "arm64"
        default: return "amd64"
        }
    }

    private static func launchAgentPlist(binaryPath: String, port: Int, logDir: String) -> String {
        """
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0">
        <dict>
            <key>Label</key>
            <string>org.weisssolutions.sift.server</string>
            <key>ProgramArguments</key>
            <array>
                <string>\(binaryPath)</string>
                <string>serve</string>
                <string>--port</string>
                <string>\(port)</string>
            </array>
            <key>RunAtLoad</key>
            <true/>
            <key>KeepAlive</key>
            <true/>
            <key>StandardOutPath</key>
            <string>\(logDir)/stdout.log</string>
            <key>StandardErrorPath</key>
            <string>\(logDir)/stderr.log</string>
        </dict>
        </plist>
        """
    }
}
