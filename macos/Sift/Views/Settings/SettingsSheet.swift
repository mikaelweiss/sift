import SwiftUI

private enum SettingsSection: String, CaseIterable, Identifiable {
    case filtering = "Categories"
    case allowlist = "Allowlist"
    case credentials = "iCloud & AI"
    case server = "Server & Macs"

    var id: String { rawValue }
}

struct SettingsSheet: View {
    @Environment(AppState.self) private var appState
    @Environment(\.dismiss) private var dismiss

    @State private var selectedSection: SettingsSection = .filtering
    @State private var draftSettings = AppSettings()
    @State private var isHydrated = false
    @State private var autoSaveTask: Task<Void, Never>?

    @State private var imapPasswordInput = ""
    @State private var aiAPIKeyInput = ""
    @State private var newCategoryName = ""
    @State private var newCategoryDescription = ""
    @State private var newAllowlistPattern = ""

    @State private var errorMessage: String?
    @State private var infoMessage: String?
    @State private var isTestingIMAP = false
    @State private var isTestingAI = false

    var body: some View {
        VStack(spacing: 0) {
            HStack {
                Text("Settings")
                    .font(.title2.bold())
                Spacer()
                Button("Done") { dismiss() }
                    .keyboardShortcut(.cancelAction)
            }
            .padding(.horizontal, 20)
            .padding(.vertical, 14)

            Divider()

            Picker("Section", selection: $selectedSection) {
                ForEach(SettingsSection.allCases) { section in
                    Text(section.rawValue).tag(section)
                }
            }
            .pickerStyle(.segmented)
            .labelsHidden()
            .padding(.horizontal, 20)
            .padding(.vertical, 12)

            Divider()

            if let errorMessage {
                HStack(spacing: 8) {
                    Image(systemName: "exclamationmark.triangle.fill")
                        .foregroundStyle(.red)
                    Text(errorMessage)
                        .font(.callout)
                        .foregroundStyle(.red)
                    Spacer()
                    Button("Dismiss") {
                        self.errorMessage = nil
                    }
                    .buttonStyle(.borderless)
                    .font(.caption)
                }
                .padding(.horizontal, 20)
                .padding(.vertical, 10)
                .background(Color.red.opacity(0.1))
                Divider()
            }

            Group {
                switch selectedSection {
                case .filtering:
                    filteringTab
                case .allowlist:
                    allowlistTab
                case .credentials:
                    credentialsTab
                case .server:
                    serverTab
                }
            }
            .padding(16)
            .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)

            if let infoMessage {
                Divider()
                HStack {
                    Text(infoMessage)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                    Spacer()
                }
                .padding(.horizontal, 20)
                .padding(.vertical, 8)
            }
        }
        .frame(width: 720, height: 600)
        .onAppear {
            draftSettings = appState.settings
            DispatchQueue.main.async {
                isHydrated = true
            }
        }
        .onDisappear {
            if autoSaveTask != nil {
                autoSaveTask?.cancel()
                autoSaveTask = nil
                Task { await persistSettings() }
            }
        }
        .onChange(of: draftSettings) { _, _ in
            scheduleAutoSave(delayMs: 350)
        }
        .onChange(of: imapPasswordInput) { _, _ in
            scheduleAutoSave(delayMs: 700)
        }
        .onChange(of: aiAPIKeyInput) { _, _ in
            scheduleAutoSave(delayMs: 700)
        }
    }

    private var filteringTab: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 18) {
                GroupBox("Categories") {
                    VStack(alignment: .leading, spacing: 8) {
                        HStack {
                            Text("Category")
                                .font(.caption.weight(.semibold))
                                .foregroundStyle(.secondary)
                            Spacer()
                            Text("Block")
                                .font(.caption.weight(.semibold))
                                .foregroundStyle(.secondary)
                                .frame(width: 54, alignment: .center)
                            Text("Report")
                                .font(.caption.weight(.semibold))
                                .foregroundStyle(.secondary)
                                .frame(width: 54, alignment: .center)
                            Spacer().frame(width: 24)
                        }
                        .padding(.bottom, 2)

                        Divider()

                        ForEach(appState.categories) { cat in
                            HStack(alignment: .center, spacing: 8) {
                                VStack(alignment: .leading, spacing: 2) {
                                    Text(cat.name).font(.body.weight(.medium))
                                    Text(cat.description)
                                        .font(.caption)
                                        .foregroundStyle(.secondary)
                                        .lineLimit(2)
                                }
                                Spacer()
                                Toggle("", isOn: Binding(
                                    get: { cat.enabled },
                                    set: { newValue in
                                        var updated = cat
                                        updated.enabled = newValue
                                        Task { await updateCategory(updated) }
                                    }
                                ))
                                .labelsHidden()
                                .frame(width: 54, alignment: .center)

                                Toggle("", isOn: Binding(
                                    get: { cat.abuseEligible },
                                    set: { newValue in
                                        var updated = cat
                                        updated.abuseEligible = newValue
                                        Task { await updateCategory(updated) }
                                    }
                                ))
                                .labelsHidden()
                                .frame(width: 54, alignment: .center)

                                if !cat.builtin {
                                    Button(role: .destructive) {
                                        Task { await deleteCategory(cat.id) }
                                    } label: {
                                        Image(systemName: "trash")
                                    }
                                    .buttonStyle(.borderless)
                                    .frame(width: 24)
                                } else {
                                    Spacer().frame(width: 24)
                                }
                            }
                            .padding(.vertical, 2)
                            Divider()
                        }

                        HStack {
                            TextField("Custom category name", text: $newCategoryName)
                                .textFieldStyle(.roundedBorder)
                            TextField("Short description", text: $newCategoryDescription)
                                .textFieldStyle(.roundedBorder)
                            Button("Add") {
                                Task { await addCategory() }
                            }
                            .disabled(newCategoryName.trimmingCharacters(in: .whitespaces).isEmpty)
                        }
                    }
                    .padding(8)
                }

                GroupBox("Spam Thresholds") {
                    VStack(alignment: .leading, spacing: 10) {
                        HStack {
                            Text("Move to Junk at: \(Int(draftSettings.junkThreshold * 100))%")
                                .frame(width: 210, alignment: .leading)
                            Slider(value: $draftSettings.junkThreshold, in: 0.50...0.99, step: 0.01)
                        }

                        Divider()

                        Toggle("Permanently delete high-confidence spam", isOn: $draftSettings.deleteEnabled)

                        HStack {
                            Text("Delete permanently at: \(Int(draftSettings.deleteThreshold * 100))%")
                                .frame(width: 210, alignment: .leading)
                            Slider(value: $draftSettings.deleteThreshold, in: 0.70...0.99, step: 0.01)
                        }
                        .disabled(!draftSettings.deleteEnabled)
                        .opacity(draftSettings.deleteEnabled ? 1 : 0.45)

                        Text(draftSettings.deleteEnabled
                             ? "All spam moves to Junk, which trains iCloud's filter. Spam at or above the delete threshold is then deleted permanently."
                             : "All detected spam moves to Junk, which trains iCloud's filter. Review it there before deleting.")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                    .padding(8)
                }

                GroupBox("Abuse Reporting") {
                    VStack(alignment: .leading, spacing: 10) {
                        Text("High-confidence spam in categories checked under Report is queued for abuse reports. Reports go to the sender's network, registrar, email service, link hosts, and phishing clearinghouses, sent from your iCloud address with your address removed from the evidence.")
                            .font(.caption)
                            .foregroundStyle(.secondary)

                        Toggle("Require approval before sending (top-right warning icon)", isOn: $draftSettings.abuseManualApproval)

                        HStack {
                            Text("Report confidence floor: \(Int(draftSettings.abuseMinConfidence * 100))%")
                                .frame(width: 210, alignment: .leading)
                            Slider(value: $draftSettings.abuseMinConfidence, in: 0.85...0.99, step: 0.01)
                        }

                        Stepper("Repeat-domain cooldown: \(draftSettings.abuseCooldownDays) days", value: $draftSettings.abuseCooldownDays, in: 1...30)

                    }
                    .padding(8)
                }
            }
            .padding(4)
        }
    }

    private var allowlistTab: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("Senders and domains listed here bypass Jev and are never moved or deleted. Built-in brand entries apply only when the email passes DMARC, so phishing that fakes those brands is still caught. Remove any you want filtered.")
                .font(.callout)
                .foregroundStyle(.secondary)

            HStack {
                TextField("Allowlist entry", text: $newAllowlistPattern, prompt: Text(verbatim: "Email address or domain (e.g. bank.com or mom@icloud.com)"))
                    .textFieldStyle(.roundedBorder)
                Button("Add") {
                    Task { await addAllowlist() }
                }
                .buttonStyle(.borderedProminent)
                .disabled(newAllowlistPattern.trimmingCharacters(in: .whitespaces).isEmpty)
            }

            List {
                ForEach(appState.allowlist) { entry in
                    HStack {
                        Image(systemName: entry.kind == "email" ? "envelope" : "globe")
                            .foregroundStyle(.secondary)
                        Text(entry.pattern)
                        if entry.builtin {
                            Text("Built-in · needs DMARC")
                                .font(.caption2)
                                .padding(.horizontal, 5)
                                .padding(.vertical, 1)
                                .background(Color.secondary.opacity(0.15), in: Capsule())
                        }
                        Spacer()
                        Text(entry.kind)
                            .font(.caption)
                            .foregroundStyle(.secondary)
                        Button(role: .destructive) {
                            Task { await removeAllowlist(entry.id) }
                        } label: {
                            Image(systemName: "trash")
                        }
                        .buttonStyle(.borderless)
                    }
                }
            }
            .listStyle(.bordered)
        }
        .padding(4)
    }

    private var credentialsTab: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                GroupBox("iCloud Mail (IMAP)") {
                    VStack(alignment: .leading, spacing: 10) {
                        TextField("iCloud Email", text: $draftSettings.imapUsername)
                            .textFieldStyle(.roundedBorder)
                        SecureField(appState.settings.hasIMAPPassword == true ? "App-Specific Password (saved, leave blank to keep)" : "App-Specific Password", text: $imapPasswordInput)
                            .textFieldStyle(.roundedBorder)
                        HStack {
                            Button(isTestingIMAP ? "Testing..." : "Test IMAP Connection") {
                                Task { await testIMAP() }
                            }
                            .disabled(isTestingIMAP)
                            Link(destination: URL(string: "https://account.apple.com/account/manage/section/security")!) {
                                Label("Create App-Specific Password", systemImage: "arrow.up.right.square")
                            }
                            .buttonStyle(.bordered)
                            Spacer()
                        }
                    }
                    .padding(8)
                }

                GroupBox("TypeSafe / OpenRouter API") {
                    VStack(alignment: .leading, spacing: 10) {
                        Picker("Provider", selection: $draftSettings.aiProvider) {
                            Text("TypeSafe").tag("typesafe")
                            Text("OpenRouter").tag("openrouter")
                        }
                        .pickerStyle(.segmented)
                        SecureField(appState.settings.hasAIAPIKey == true ? "API Key (saved, leave blank to keep)" : "API Key", text: $aiAPIKeyInput)
                            .textFieldStyle(.roundedBorder)
                        TextField("Model", text: $draftSettings.aiModel)
                            .textFieldStyle(.roundedBorder)
                        HStack {
                            Button(isTestingAI ? "Testing..." : "Test AI Key") {
                                Task { await testAI() }
                            }
                            .disabled(isTestingAI)
                            Link(destination: URL(string: draftSettings.aiProvider == "openrouter" ? "https://openrouter.ai/settings/keys" : "https://console.typesafe.ai/keys")!) {
                                Label(draftSettings.aiProvider == "openrouter" ? "Get OpenRouter API Key" : "Get TypeSafe API Key", systemImage: "arrow.up.right.square")
                            }
                            .buttonStyle(.bordered)
                            Spacer()
                        }
                    }
                    .padding(8)
                }
            }
            .padding(4)
        }
    }

    private var serverTab: some View {
        VStack(alignment: .leading, spacing: 14) {
            if let conn = appState.connection {
                GroupBox("Connected Server") {
                    VStack(alignment: .leading, spacing: 6) {
                        Text("Host: \(conn.host):\(conn.port) (\(conn.isLocal ? "This Mac" : "Remote SSH"))")
                            .font(.callout)
                        if let health = appState.health {
                            Text("Version: v\(health.version) (\(health.os)/\(health.arch)) · Bundled: v\(appState.bundledServerVersion)")
                                .font(.caption)
                                .foregroundStyle(.secondary)
                        }
                        Text("TLS SHA-256: \(conn.tlsFingerprint.prefix(24))...")
                            .font(.caption.monospaced())
                            .foregroundStyle(.secondary)
                        HStack {
                            Button(appState.isUpdatingServer ? "Updating..." : "Reinstall / Update Server Binary") {
                                Task { await appState.updateServerBinary() }
                            }
                            .disabled(appState.isUpdatingServer)
                            Spacer()
                            Button("Sign Out This Mac", role: .destructive) {
                                Task {
                                    await appState.signOut()
                                    dismiss()
                                }
                            }
                        }
                        .padding(.top, 4)
                    }
                    .padding(8)
                    .frame(maxWidth: .infinity, alignment: .leading)
                }
            }

            Text("Paired Macs")
                .font(.headline)

            List {
                ForEach(appState.devices) { device in
                    HStack {
                        Image(systemName: "laptopcomputer")
                        VStack(alignment: .leading) {
                            HStack(spacing: 6) {
                                Text(device.name).font(.body.weight(.medium))
                                if device.id == appState.connection?.deviceID {
                                    Text("This Mac")
                                        .font(.caption2)
                                        .padding(.horizontal, 6)
                                        .padding(.vertical, 2)
                                        .background(Color.accentColor.opacity(0.15), in: Capsule())
                                }
                            }
                            Text("Last seen: \(device.lastSeenAt)")
                                .font(.caption)
                                .foregroundStyle(.secondary)
                        }
                        Spacer()
                        if device.id != appState.connection?.deviceID {
                            Button("Revoke", role: .destructive) {
                                Task { await revokeDevice(device.id) }
                            }
                            .buttonStyle(.bordered)
                            .controlSize(.small)
                        }
                    }
                }
            }
            .listStyle(.bordered)
        }
        .padding(4)
    }

    private func scheduleAutoSave(delayMs: UInt64) {
        guard isHydrated else { return }
        autoSaveTask?.cancel()
        autoSaveTask = Task {
            try? await Task.sleep(nanoseconds: delayMs * 1_000_000)
            guard !Task.isCancelled else { return }
            await persistSettings()
            autoSaveTask = nil
        }
    }

    private func persistSettings() async {
        guard let client = appState.apiClient else { return }
        var payload = draftSettings
        payload.abuseEnabled = true
        if !imapPasswordInput.isEmpty { payload.imapPassword = imapPasswordInput }
        if !aiAPIKeyInput.isEmpty { payload.aiAPIKey = aiAPIKeyInput }
        do {
            let updated = try await client.updateSettings(payload)
            appState.settings = updated
            errorMessage = nil
        } catch {
            errorMessage = "Failed to save settings: \(error.localizedDescription)"
        }
    }

    private func testIMAP() async {
        guard let client = appState.apiClient else { return }
        isTestingIMAP = true
        defer { isTestingIMAP = false }
        do {
            let res = try await client.validateIMAP(
                host: draftSettings.imapHost,
                port: draftSettings.imapPort,
                username: draftSettings.imapUsername,
                password: imapPasswordInput
            )
            if res.ok {
                errorMessage = nil
                infoMessage = "iCloud IMAP connection succeeded."
            } else {
                errorMessage = "IMAP test failed: \(res.error)"
            }
        } catch {
            errorMessage = "IMAP test failed: \(error.localizedDescription)"
        }
    }

    private func testAI() async {
        guard let client = appState.apiClient else { return }
        isTestingAI = true
        defer { isTestingAI = false }
        do {
            let res = try await client.validateAI(
                provider: draftSettings.aiProvider,
                apiKey: aiAPIKeyInput,
                model: draftSettings.aiModel
            )
            if res.ok {
                errorMessage = nil
                infoMessage = "Jev API key verified."
            } else {
                errorMessage = "AI test failed: \(res.error)"
            }
        } catch {
            errorMessage = "AI test failed: \(error.localizedDescription)"
        }
    }

    private func updateCategory(_ cat: Category) async {
        guard let client = appState.apiClient else { return }
        do {
            _ = try await client.updateCategory(cat)
            appState.categories = try await client.listCategories()
            errorMessage = nil
        } catch {
            errorMessage = "Failed to save \(cat.name): \(error.localizedDescription)"
        }
    }

    private func addCategory() async {
        guard let client = appState.apiClient else { return }
        do {
            _ = try await client.createCategory(
                name: newCategoryName.trimmingCharacters(in: .whitespaces),
                description: newCategoryDescription.trimmingCharacters(in: .whitespaces),
                enabled: true,
                abuseEligible: false
            )
            newCategoryName = ""
            newCategoryDescription = ""
            appState.categories = try await client.listCategories()
            errorMessage = nil
        } catch {
            errorMessage = "Failed to add category: \(error.localizedDescription)"
        }
    }

    private func deleteCategory(_ id: String) async {
        guard let client = appState.apiClient else { return }
        do {
            try await client.deleteCategory(id: id)
            appState.categories = try await client.listCategories()
            errorMessage = nil
        } catch {
            errorMessage = "Failed to delete category: \(error.localizedDescription)"
        }
    }

    private func addAllowlist() async {
        guard let client = appState.apiClient else { return }
        let pattern = newAllowlistPattern.trimmingCharacters(in: .whitespaces)
        let kind = pattern.contains("@") ? "email" : "domain"
        do {
            _ = try await client.addAllowlist(pattern: pattern, kind: kind)
            newAllowlistPattern = ""
            appState.allowlist = try await client.listAllowlist()
            errorMessage = nil
        } catch {
            errorMessage = "Failed to add allowlist entry: \(error.localizedDescription)"
        }
    }

    private func removeAllowlist(_ id: Int64) async {
        guard let client = appState.apiClient else { return }
        do {
            try await client.deleteAllowlist(id: id)
            appState.allowlist = try await client.listAllowlist()
            errorMessage = nil
        } catch {
            errorMessage = "Failed to remove allowlist entry: \(error.localizedDescription)"
        }
    }

    private func revokeDevice(_ id: String) async {
        guard let client = appState.apiClient else { return }
        do {
            try await client.revokeDevice(id: id)
            appState.devices = try await client.listDevices()
            errorMessage = nil
        } catch {
            errorMessage = "Failed to revoke device: \(error.localizedDescription)"
        }
    }
}
