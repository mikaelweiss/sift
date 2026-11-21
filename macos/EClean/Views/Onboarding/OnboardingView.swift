import AppKit
import SwiftUI

private enum OnboardingStep: Int, CaseIterable {
    case selectHost
    case pairExisting
    case credentials
    case categories
    case deploy
}

private struct DraftCategory: Identifiable {
    var id: String
    var name: String
    var description: String
    var enabled: Bool
    var isCustom: Bool = false
}

struct OnboardingView: View {
    @Environment(AppState.self) private var appState
    @State private var discovery = HostDiscovery()
    @State private var step: OnboardingStep = .selectHost

    // Step 1: Host & SSH
    @State private var selectedHost: DiscoveredHost?
    @State private var useManualHost = false
    @State private var manualHost = ""
    @State private var serverPort = 8443
    @State private var sshUser = NSUserName()
    @State private var selectedKeyPath = ""
    @State private var isCheckingHost = false

    // Pairing branch
    @State private var existingFingerprint = ""
    @State private var existingPort = 8443
    @State private var pairRequestID = ""
    @State private var pairVerificationCode = ""
    @State private var cliPairCode = ""
    @State private var pairStatusText = "Waiting for approval on an already paired Mac..."
    @State private var pairPollTask: Task<Void, Never>?

    // Step 2: Credentials
    @State private var icloudEmail = ""
    @State private var icloudAppPassword = ""
    @State private var aiProvider = "typesafe"
    @State private var aiAPIKey = ""
    @State private var aiModel = "jev-latest"

    // Step 3: Categories & Action
    @State private var draftCategories: [DraftCategory] = [
        DraftCategory(id: "phishing_scams", name: "Phishing & Scams", description: "Fraudulent emails, credential theft, fake invoices.", enabled: true),
        DraftCategory(id: "marketing_promotions", name: "Marketing & Promotions", description: "Commercial promos, discounts, and mass advertising.", enabled: true),
        DraftCategory(id: "cold_sales", name: "Cold Sales & Outreach", description: "Unsolicited B2B pitches and recruiter blasts.", enabled: true),
        DraftCategory(id: "newsletters", name: "Newsletters", description: "Mailing lists, digests, and editorial updates.", enabled: false),
        DraftCategory(id: "crypto_gambling", name: "Crypto & Gambling", description: "Unsolicited crypto schemes and online casino promos.", enabled: true),
        DraftCategory(id: "political_fundraising", name: "Political & Fundraising", description: "Campaign solicitations and donation drives.", enabled: false),
    ]
    @State private var newCategoryName = ""
    @State private var newCategoryDescription = ""
    @State private var spamAction = "trash"

    // Step 4: Deploy progress
    @State private var deployLogs: [String] = []
    @State private var isDeploying = false
    @State private var errorMessage: String?

    var body: some View {
        VStack(spacing: 0) {
            header
            Divider()
            ScrollView {
                VStack(alignment: .leading, spacing: 20) {
                    if let errorMessage {
                        HStack(spacing: 8) {
                            Image(systemName: "exclamationmark.triangle.fill")
                                .foregroundStyle(.orange)
                            Text(errorMessage)
                                .font(.callout)
                            Spacer()
                        }
                        .padding(12)
                        .background(Color.orange.opacity(0.12), in: RoundedRectangle(cornerRadius: 8))
                    }

                    switch step {
                    case .selectHost:
                        selectHostStep
                    case .pairExisting:
                        pairExistingStep
                    case .credentials:
                        credentialsStep
                    case .categories:
                        categoriesStep
                    case .deploy:
                        deployStep
                    }
                }
                .padding(28)
                .frame(maxWidth: 680, alignment: .leading)
                .frame(maxWidth: .infinity)
            }
            Divider()
            footer
        }
        .onAppear {
            discovery.startDiscovery()
            if selectedKeyPath.isEmpty, let first = discovery.sshKeys.first {
                selectedKeyPath = first.path
            }
        }
        .onDisappear {
            discovery.stopDiscovery()
            pairPollTask?.cancel()
        }
    }

    private var header: some View {
        HStack {
            VStack(alignment: .leading, spacing: 4) {
                Text("Welcome to EClean")
                    .font(.title2.bold())
                Text(stepSubtitle)
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
            }
            Spacer()
            if step != .pairExisting {
                Text("Step \(min(stepNumber, 4)) of 4")
                    .font(.caption.monospacedDigit())
                    .padding(.horizontal, 10)
                    .padding(.vertical, 4)
                    .background(.quaternary, in: Capsule())
            }
        }
        .padding(.horizontal, 28)
        .padding(.vertical, 18)
    }

    private var stepNumber: Int {
        switch step {
        case .selectHost: return 1
        case .pairExisting: return 1
        case .credentials: return 2
        case .categories: return 3
        case .deploy: return 4
        }
    }

    private var stepSubtitle: String {
        switch step {
        case .selectHost: return "Choose where your 24/7 spam filter server will run."
        case .pairExisting: return "EClean is already running on this machine. Pair this Mac to connect."
        case .credentials: return "Connect iCloud Mail and your TypeSafe or OpenRouter API key."
        case .categories: return "Choose which spam categories to block and how to handle matches."
        case .deploy: return "Installing and configuring your EClean server."
        }
    }

    private var selectHostStep: some View {
        VStack(alignment: .leading, spacing: 16) {
            HStack {
                Text("Available Computers")
                    .font(.headline)
                Spacer()
                if discovery.isScanning {
                    ProgressView().controlSize(.small)
                }
                Button("Rescan") {
                    discovery.startDiscovery()
                }
                .buttonStyle(.bordered)
                .controlSize(.small)
            }

            VStack(spacing: 8) {
                ForEach(discovery.hosts) { host in
                    let isSelected = !useManualHost && selectedHost?.id == host.id
                    Button {
                        useManualHost = false
                        selectedHost = host
                    } label: {
                        HStack {
                            Image(systemName: host.isLocal ? "laptopcomputer" : (host.source == .tailscale ? "network" : "wifi"))
                                .frame(width: 22)
                            VStack(alignment: .leading, spacing: 2) {
                                Text(host.name)
                                    .font(.body.weight(.medium))
                                Text("\(host.address) (\(host.source.rawValue)\(host.osHint.map { ", \($0)" } ?? ""))")
                                    .font(.caption)
                                    .foregroundStyle(.secondary)
                            }
                            Spacer()
                            if isSelected {
                                Image(systemName: "checkmark.circle.fill")
                                    .foregroundStyle(Color.accentColor)
                            }
                        }
                        .padding(10)
                        .background(isSelected ? Color.accentColor.opacity(0.12) : Color.secondary.opacity(0.06), in: RoundedRectangle(cornerRadius: 8))
                    }
                    .buttonStyle(.plain)
                }

                Button {
                    useManualHost = true
                    selectedHost = nil
                } label: {
                    HStack {
                        Image(systemName: "terminal")
                            .frame(width: 22)
                        Text("Enter hostname or IP manually")
                            .font(.body.weight(.medium))
                        Spacer()
                        if useManualHost {
                            Image(systemName: "checkmark.circle.fill")
                                .foregroundStyle(Color.accentColor)
                        }
                    }
                    .padding(10)
                    .background(useManualHost ? Color.accentColor.opacity(0.12) : Color.secondary.opacity(0.06), in: RoundedRectangle(cornerRadius: 8))
                }
                .buttonStyle(.plain)
            }

            if useManualHost {
                TextField("Hostname or IP", text: $manualHost, prompt: Text(verbatim: "Hostname or IP (e.g. home-server.ts.net or 192.168.1.50)"))
                    .textFieldStyle(.roundedBorder)
            }

            if !effectiveIsLocal {
                GroupBox("SSH Connection") {
                    VStack(alignment: .leading, spacing: 10) {
                        HStack {
                            Text("Username")
                                .frame(width: 90, alignment: .leading)
                            TextField("SSH user", text: $sshUser)
                                .textFieldStyle(.roundedBorder)
                        }
                        HStack {
                            Text("SSH Key")
                                .frame(width: 90, alignment: .leading)
                            Picker("SSH Key", selection: $selectedKeyPath) {
                                Text("Default ssh-agent / ~/.ssh/config").tag("")
                                ForEach(discovery.sshKeys) { key in
                                    Text(key.name).tag(key.path)
                                }
                                if !selectedKeyPath.isEmpty && !discovery.sshKeys.contains(where: { $0.path == selectedKeyPath }) {
                                    Text(URL(fileURLWithPath: selectedKeyPath).lastPathComponent).tag(selectedKeyPath)
                                }
                            }
                            .labelsHidden()
                            Button("Browse...") {
                                pickSSHKey()
                            }
                        }
                    }
                    .padding(6)
                }
            }
        }
    }

    private var pairExistingStep: some View {
        VStack(alignment: .leading, spacing: 20) {
            GroupBox("Approve on an Existing Paired Mac") {
                VStack(alignment: .leading, spacing: 10) {
                    Text("A pairing request has been sent to your already connected Mac app. Confirm the code below matches:")
                        .font(.callout)
                        .foregroundStyle(.secondary)
                    if !pairVerificationCode.isEmpty {
                        Text(pairVerificationCode)
                            .font(.system(size: 34, weight: .bold, design: .monospaced))
                            .tracking(6)
                            .padding(.vertical, 6)
                    }
                    HStack(spacing: 8) {
                        ProgressView().controlSize(.small)
                        Text(pairStatusText)
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                }
                .padding(8)
                .frame(maxWidth: .infinity, alignment: .leading)
            }

            GroupBox("Or Enter Code from Server CLI") {
                VStack(alignment: .leading, spacing: 10) {
                    Text("If no other Mac is paired or online, run `eclean pair` on the server and enter the 6-digit code:")
                        .font(.callout)
                        .foregroundStyle(.secondary)
                    HStack {
                        TextField("6-digit code", text: $cliPairCode)
                            .textFieldStyle(.roundedBorder)
                            .frame(width: 180)
                        Button("Pair with Code") {
                            Task { await redeemCLICode() }
                        }
                        .buttonStyle(.borderedProminent)
                        .disabled(cliPairCode.trimmingCharacters(in: .whitespaces).count < 6)
                    }
                }
                .padding(8)
                .frame(maxWidth: .infinity, alignment: .leading)
            }
        }
    }

    private var credentialsStep: some View {
        VStack(alignment: .leading, spacing: 18) {
            GroupBox("iCloud Mail (IMAP)") {
                VStack(alignment: .leading, spacing: 10) {
                    Text("Generate an app-specific password at account.apple.com under Sign-In and Security -> App-Specific Passwords.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                    Link("Open account.apple.com", destination: URL(string: "https://account.apple.com")!)
                        .font(.caption)
                    TextField("iCloud Email", text: $icloudEmail, prompt: Text(verbatim: "iCloud Email (e.g. you@icloud.com)"))
                        .textFieldStyle(.roundedBorder)
                    SecureField("App-Specific Password (xxxx-xxxx-xxxx-xxxx)", text: $icloudAppPassword)
                        .textFieldStyle(.roundedBorder)
                }
                .padding(8)
            }

            GroupBox("Jev System One API") {
                VStack(alignment: .leading, spacing: 10) {
                    Picker("Provider", selection: $aiProvider) {
                        Text("TypeSafe (api.typesafe.ai)").tag("typesafe")
                        Text("OpenRouter (openrouter.ai)").tag("openrouter")
                    }
                    .pickerStyle(.segmented)
                    .onChange(of: aiProvider) { _, newValue in
                        aiModel = newValue == "openrouter" ? "typesafe/jev-latest" : "jev-latest"
                    }

                    SecureField("API Key", text: $aiAPIKey)
                        .textFieldStyle(.roundedBorder)
                    TextField("Model", text: $aiModel)
                        .textFieldStyle(.roundedBorder)
                }
                .padding(8)
            }
        }
    }

    private var categoriesStep: some View {
        VStack(alignment: .leading, spacing: 18) {
            GroupBox("Blocked Categories") {
                VStack(alignment: .leading, spacing: 8) {
                    ForEach($draftCategories) { $cat in
                        Toggle(isOn: $cat.enabled) {
                            VStack(alignment: .leading, spacing: 2) {
                                Text(cat.name).font(.body.weight(.medium))
                                Text(cat.description).font(.caption).foregroundStyle(.secondary)
                            }
                        }
                        .padding(.vertical, 2)
                    }
                    Divider()
                    HStack {
                        TextField("Custom category name", text: $newCategoryName)
                            .textFieldStyle(.roundedBorder)
                        TextField("Short description", text: $newCategoryDescription)
                            .textFieldStyle(.roundedBorder)
                        Button("Add") {
                            let name = newCategoryName.trimmingCharacters(in: .whitespaces)
                            guard !name.isEmpty else { return }
                            draftCategories.append(DraftCategory(
                                id: "custom_\(UUID().uuidString.prefix(8))",
                                name: name,
                                description: newCategoryDescription.trimmingCharacters(in: .whitespaces),
                                enabled: true,
                                isCustom: true
                            ))
                            newCategoryName = ""
                            newCategoryDescription = ""
                        }
                        .disabled(newCategoryName.trimmingCharacters(in: .whitespaces).isEmpty)
                    }
                }
                .padding(8)
            }

            GroupBox("Spam Action") {
                VStack(alignment: .leading, spacing: 8) {
                    Picker("When spam is detected", selection: $spamAction) {
                        Text("Move to Trash (threshold 85%)").tag("trash")
                        Text("Delete Permanently (threshold 95%)").tag("delete")
                    }
                    .pickerStyle(.radioGroup)
                    Text("You can adjust confidence thresholds and add allowlist rules anytime in Settings.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                .padding(8)
            }
        }
    }

    private var deployStep: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack(spacing: 10) {
                if isDeploying {
                    ProgressView().controlSize(.small)
                }
                Text(isDeploying ? "Setting up your EClean server..." : "Setup status")
                    .font(.headline)
            }
            VStack(alignment: .leading, spacing: 6) {
                ForEach(deployLogs, id: \.self) { line in
                    HStack(spacing: 8) {
                        Image(systemName: "checkmark.circle.fill")
                            .foregroundStyle(.green)
                            .font(.caption)
                        Text(line)
                            .font(.callout.monospaced())
                    }
                }
            }
            .padding(12)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(Color.secondary.opacity(0.08), in: RoundedRectangle(cornerRadius: 8))
        }
    }

    private var footer: some View {
        HStack {
            if step != .selectHost && !isDeploying {
                Button("Back") {
                    pairPollTask?.cancel()
                    errorMessage = nil
                    switch step {
                    case .pairExisting, .credentials:
                        step = .selectHost
                    case .categories:
                        step = .credentials
                    case .deploy:
                        step = .categories
                    case .selectHost:
                        break
                    }
                }
            }
            Spacer()
            switch step {
            case .selectHost:
                Button {
                    Task { await inspectSelectedHost() }
                } label: {
                    if isCheckingHost {
                        ProgressView().controlSize(.small)
                    } else {
                        Text("Continue")
                    }
                }
                .buttonStyle(.borderedProminent)
                .disabled(effectiveHostAddress.isEmpty || isCheckingHost)

            case .pairExisting:
                EmptyView()

            case .credentials:
                Button("Continue") {
                    errorMessage = nil
                    step = .categories
                }
                .buttonStyle(.borderedProminent)
                .disabled(icloudEmail.isEmpty || icloudAppPassword.isEmpty || aiAPIKey.isEmpty)

            case .categories:
                Button("Install & Start Server") {
                    step = .deploy
                    Task { await runFullDeploy() }
                }
                .buttonStyle(.borderedProminent)

            case .deploy:
                if !isDeploying {
                    Button("Retry") {
                        Task { await runFullDeploy() }
                    }
                    .buttonStyle(.borderedProminent)
                }
            }
        }
        .padding(.horizontal, 28)
        .padding(.vertical, 14)
    }

    private var effectiveIsLocal: Bool {
        !useManualHost && (selectedHost?.isLocal ?? false)
    }

    private var effectiveHostAddress: String {
        if useManualHost {
            return manualHost.trimmingCharacters(in: .whitespacesAndNewlines)
        }
        return selectedHost?.address ?? ""
    }

    private func pickSSHKey() {
        let panel = NSOpenPanel()
        panel.canChooseFiles = true
        panel.canChooseDirectories = false
        panel.showsHiddenFiles = true
        panel.directoryURL = FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent(".ssh")
        if panel.runModal() == .OK, let url = panel.url {
            selectedKeyPath = url.path
        }
    }

    private func inspectSelectedHost() async {
        errorMessage = nil
        isCheckingHost = true
        defer { isCheckingHost = false }

        let target = DeployTarget(
            isLocal: effectiveIsLocal,
            host: effectiveHostAddress,
            sshUser: sshUser.trimmingCharacters(in: .whitespaces),
            sshKeyPath: selectedKeyPath.isEmpty ? nil : selectedKeyPath,
            port: serverPort
        )

        // First probe if an eclean server is already reachable directly over HTTPS.
        if let probeURL = URL(string: "https://\(target.host):\(target.port)") {
            let probeClient = APIClient(baseURL: probeURL, token: nil, tlsFingerprint: nil)
            if let health = try? await probeClient.health(), !health.tlsFingerprint.isEmpty {
                existingFingerprint = health.tlsFingerprint
                existingPort = target.port
                step = .pairExisting
                await beginLivePairing()
                return
            }
        }

        do {
            let info = try await SSHDeployer.inspectHost(target: target)
            if info.alreadyInstalled, let fp = info.existingFingerprint, !fp.isEmpty {
                existingFingerprint = fp
                existingPort = info.existingPort
                step = .pairExisting
                await beginLivePairing()
            } else {
                step = .credentials
            }
        } catch {
            errorMessage = "SSH connection failed: \(error.localizedDescription)"
        }
    }

    private func beginLivePairing() async {
        pairPollTask?.cancel()
        guard let url = URL(string: "https://\(effectiveHostAddress):\(existingPort)") else { return }
        let client = APIClient(baseURL: url, token: nil, tlsFingerprint: existingFingerprint)
        let deviceName = Host.current().localizedName ?? "Mac"
        do {
            let req = try await client.requestPair(deviceName: deviceName)
            pairRequestID = req.requestID
            pairVerificationCode = req.verificationCode
            pairStatusText = "Waiting for approval on an already paired Mac..."

            pairPollTask = Task {
                while !Task.isCancelled {
                    try? await Task.sleep(nanoseconds: 2_000_000_000)
                    guard let st = try? await client.pairStatus(requestID: req.requestID) else { continue }
                    if st.status == "approved", let deviceID = st.deviceID, let token = st.token {
                        let conn = ServerConnection(
                            host: effectiveHostAddress,
                            port: existingPort,
                            tlsFingerprint: existingFingerprint,
                            deviceID: deviceID,
                            deviceToken: token,
                            isLocal: effectiveIsLocal,
                            sshUser: sshUser,
                            sshKeyPath: selectedKeyPath.isEmpty ? nil : selectedKeyPath
                        )
                        await appState.connect(to: conn)
                        return
                    }
                    if st.status == "denied" {
                        pairStatusText = "Pairing request was denied."
                        return
                    }
                    if st.status == "expired" {
                        pairStatusText = "Pairing request expired. Use `eclean pair` or go back and retry."
                        return
                    }
                }
            }
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    private func redeemCLICode() async {
        errorMessage = nil
        guard let url = URL(string: "https://\(effectiveHostAddress):\(existingPort)") else { return }
        let client = APIClient(baseURL: url, token: nil, tlsFingerprint: existingFingerprint)
        let deviceName = Host.current().localizedName ?? "Mac"
        do {
            let res = try await client.redeemPair(code: cliPairCode.trimmingCharacters(in: .whitespaces), deviceName: deviceName)
            pairPollTask?.cancel()
            let conn = ServerConnection(
                host: effectiveHostAddress,
                port: existingPort,
                tlsFingerprint: existingFingerprint,
                deviceID: res.deviceID,
                deviceToken: res.token,
                isLocal: effectiveIsLocal,
                sshUser: sshUser,
                sshKeyPath: selectedKeyPath.isEmpty ? nil : selectedKeyPath
            )
            await appState.connect(to: conn)
        } catch {
            errorMessage = "Pairing failed: \(error.localizedDescription)"
        }
    }

    private func runFullDeploy() async {
        errorMessage = nil
        isDeploying = true
        deployLogs = []
        defer { isDeploying = false }

        let target = DeployTarget(
            isLocal: effectiveIsLocal,
            host: effectiveHostAddress,
            sshUser: sshUser.trimmingCharacters(in: .whitespaces),
            sshKeyPath: selectedKeyPath.isEmpty ? nil : selectedKeyPath,
            port: serverPort
        )

        do {
            let result = try await SSHDeployer.deployOrUpdate(target: target, isUpdate: false) { msg in
                Task { @MainActor in
                    deployLogs.append(msg)
                }
            }

            guard let code = result.pairingCode else {
                existingFingerprint = result.tlsFingerprint
                existingPort = result.port
                step = .pairExisting
                await beginLivePairing()
                return
            }

            deployLogs.append("Pairing this Mac over pinned TLS...")
            let baseURL = URL(string: "https://\(result.host):\(result.port)")!
            let bootstrapClient = APIClient(baseURL: baseURL, token: nil, tlsFingerprint: result.tlsFingerprint)
            let deviceName = Host.current().localizedName ?? "Mac"
            let paired = try await bootstrapClient.redeemPair(code: code, deviceName: deviceName)

            let conn = ServerConnection(
                host: result.host,
                port: result.port,
                tlsFingerprint: result.tlsFingerprint,
                deviceID: paired.deviceID,
                deviceToken: paired.token,
                isLocal: effectiveIsLocal,
                sshUser: sshUser,
                sshKeyPath: selectedKeyPath.isEmpty ? nil : selectedKeyPath
            )
            let client = APIClient(connection: conn)

            deployLogs.append("Saving iCloud Mail and AI settings...")
            var cfg = AppSettings()
            cfg.imapUsername = icloudEmail.trimmingCharacters(in: .whitespaces)
            cfg.imapPassword = icloudAppPassword.trimmingCharacters(in: .whitespaces)
            cfg.aiProvider = aiProvider
            cfg.aiAPIKey = aiAPIKey.trimmingCharacters(in: .whitespaces)
            cfg.aiModel = aiModel.trimmingCharacters(in: .whitespaces)
            cfg.spamAction = spamAction
            _ = try await client.updateSettings(cfg)

            deployLogs.append("Applying selected spam categories...")
            let existingCats = try await client.listCategories()
            for draft in draftCategories {
                if draft.isCustom {
                    _ = try await client.createCategory(name: draft.name, description: draft.description, enabled: draft.enabled, abuseEligible: false)
                } else if var match = existingCats.first(where: { $0.id == draft.id }) {
                    match.enabled = draft.enabled
                    _ = try await client.updateCategory(match)
                }
            }

            deployLogs.append("Verifying iCloud IMAP and Jev API...")
            let imapCheck = try await client.validateIMAP(host: cfg.imapHost, port: cfg.imapPort, username: cfg.imapUsername, password: cfg.imapPassword ?? "")
            if !imapCheck.ok {
                deployLogs.append("Warning: IMAP check reported \(imapCheck.error)")
            }
            let aiCheck = try await client.validateAI(provider: cfg.aiProvider, apiKey: cfg.aiAPIKey ?? "", model: cfg.aiModel)
            if !aiCheck.ok {
                deployLogs.append("Warning: AI check reported \(aiCheck.error)")
            }

            deployLogs.append("Done!")
            await appState.connect(to: conn)
        } catch {
            errorMessage = error.localizedDescription
        }
    }
}
