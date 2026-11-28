import SwiftUI

struct AbuseReviewSheet: View {
    @Environment(AppState.self) private var appState
    @Environment(\.dismiss) private var dismiss

    private enum Tab: String, CaseIterable, Identifiable {
        case queue = "Waiting for Approval"
        case sent = "Sent Reports"
        var id: String { rawValue }
    }

    @State private var tab: Tab
    @State private var history: [AbuseHistoryEntry] = []
    @State private var bans: [AbuseReply] = []
    @State private var formOnlyDomains: [String] = []
    @State private var busyIDs: Set<Int64> = []
    @State private var isSyncingReplies = false
    @State private var syncStatus: String?
    @State private var errorMessage: String?

    init(initialShowSent: Bool = false) {
        _tab = State(initialValue: initialShowSent ? .sent : .queue)
    }

    private var anySending: Bool { appState.abuseQueue.contains(where: \.isSending) }

    var body: some View {
        VStack(spacing: 0) {
            HStack {
                Image(systemName: "exclamationmark.triangle.fill")
                    .foregroundStyle(.yellow)
                Text("Abuse Reports")
                    .font(.title3.bold())
                Spacer()
                Picker("", selection: $tab) {
                    ForEach(Tab.allCases) { Text($0.rawValue).tag($0) }
                }
                .pickerStyle(.segmented)
                .labelsHidden()
                .frame(width: 320)
                Button("Done") { dismiss() }
                    .keyboardShortcut(.cancelAction)
            }
            .padding(.horizontal, 20)
            .padding(.vertical, 14)

            Divider()

            if let errorMessage {
                HStack {
                    Text(errorMessage)
                        .font(.caption)
                        .foregroundStyle(.red)
                    Spacer()
                }
                .padding(.horizontal, 20)
                .padding(.vertical, 8)
                Divider()
            }

            switch tab {
            case .queue: queueList
            case .sent: historyList
            }
        }
        .frame(width: 720, height: 560)
        .task { await refresh() }
        .task(id: anySending) {
            while anySending {
                try? await Task.sleep(nanoseconds: 2_000_000_000)
                if Task.isCancelled { break }
                await refresh()
            }
        }
    }

    @ViewBuilder
    private var queueList: some View {
        if appState.abuseQueue.isEmpty {
            emptyState(icon: "checkmark.seal.fill", title: "Nothing waiting for approval", detail: "High-confidence phishing, scam and adult spam from the last 7 days appears here.")
        } else {
            ScrollView {
                VStack(spacing: 12) {
                    ForEach(appState.abuseQueue) { queueRow($0) }
                }
                .padding(18)
            }
        }
    }

    @ViewBuilder
    private var historyList: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 14) {
                HStack(spacing: 10) {
                    if !bans.isEmpty {
                        HStack(spacing: 6) {
                            Image(systemName: "checkmark.shield.fill")
                                .foregroundStyle(.green)
                            Text("\(appState.bannedCount) \(appState.bannedCount == 1 ? "confirmed ban" : "confirmed bans")")
                                .font(.callout.weight(.semibold))
                        }
                    }
                    if let syncStatus {
                        Text(syncStatus)
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                    Spacer()
                    Button {
                        Task { await syncReplies() }
                    } label: {
                        HStack(spacing: 5) {
                            if isSyncingReplies {
                                ProgressView().controlSize(.mini)
                            } else {
                                Image(systemName: "arrow.clockwise")
                            }
                            Text(isSyncingReplies ? "Checking..." : "Check Replies")
                        }
                    }
                    .controlSize(.small)
                    .disabled(isSyncingReplies)
                }

                if !bans.isEmpty {
                    GroupBox {
                        VStack(alignment: .leading, spacing: 8) {
                            Text("Confirmed Bans & Takedowns")
                                .font(.caption.weight(.semibold))
                                .foregroundStyle(.green)
                            ForEach(bans) { ban in
                                VStack(alignment: .leading, spacing: 2) {
                                    HStack(spacing: 6) {
                                        Image(systemName: "checkmark.shield.fill")
                                            .foregroundStyle(.green)
                                            .font(.caption)
                                        Text(ban.reportedDomain.isEmpty ? ban.subject : ban.reportedDomain)
                                            .font(.callout.weight(.semibold))
                                        Text("· \(ban.responder)")
                                            .font(.caption)
                                            .foregroundStyle(.secondary)
                                            .lineLimit(1)
                                        Spacer()
                                        Text(formattedDate(ban.receivedAt))
                                            .font(.caption)
                                            .foregroundStyle(.secondary)
                                    }
                                    if !ban.snippet.isEmpty {
                                        Text(ban.snippet)
                                            .font(.caption)
                                            .foregroundStyle(.secondary)
                                            .lineLimit(2)
                                            .padding(.leading, 18)
                                    }
                                }
                            }
                        }
                        .padding(6)
                        .frame(maxWidth: .infinity, alignment: .leading)
                    }
                }

                if history.isEmpty && bans.isEmpty {
                    emptyState(icon: "paperplane", title: "No reports sent yet", detail: "Approved reports show here with the result for every recipient.")
                        .padding(.top, 80)
                } else {
                    ForEach(history) { historyRow($0) }
                }

                if !formOnlyDomains.isEmpty {
                    DisclosureGroup("Auto-skipped web-form desks (\(formOnlyDomains.count))") {
                        VStack(alignment: .leading, spacing: 6) {
                            Text("These abuse desks replied that they do not accept emailed reports. Sift skips them automatically.")
                                .font(.caption)
                                .foregroundStyle(.secondary)
                            ForEach(formOnlyDomains, id: \.self) { domain in
                                HStack {
                                    Text(domain)
                                        .font(.caption.monospaced())
                                    Spacer()
                                    Button("Remove") {
                                        Task { await removeFormOnlyDomain(domain) }
                                    }
                                    .buttonStyle(.borderless)
                                    .font(.caption)
                                }
                            }
                        }
                        .padding(.top, 6)
                    }
                    .font(.caption)
                }
            }
            .padding(18)
        }
    }

    private func emptyState(icon: String, title: String, detail: String) -> some View {
        VStack(spacing: 10) {
            Image(systemName: icon)
                .font(.system(size: 36))
                .foregroundStyle(.secondary)
            Text(title)
                .font(.headline)
            Text(detail)
                .font(.callout)
                .foregroundStyle(.secondary)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    private func queueRow(_ item: AbuseQueueItem) -> some View {
        let isBusy = busyIDs.contains(item.id) || item.isSending
        return GroupBox {
            VStack(alignment: .leading, spacing: 8) {
                HStack(alignment: .top) {
                    VStack(alignment: .leading, spacing: 4) {
                        HStack(spacing: 8) {
                            Text(item.rootDomain)
                                .font(.headline)
                            capsule("\(item.hitCount) \(item.hitCount == 1 ? "email" : "emails")", color: .secondary)
                            if item.repeatOffense {
                                capsule("Repeat Offense", color: .orange)
                            }
                        }
                        Text("Subject: \(item.subject.isEmpty ? "(No subject)" : item.subject)")
                            .font(.callout)
                            .lineLimit(1)
                        Text("\(item.sender) · \(item.categoryID) (\(Int(item.confidence * 100))%)")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                    Spacer()
                    if item.isSending {
                        HStack(spacing: 6) {
                            ProgressView().controlSize(.small)
                            Text("Sending...")
                                .font(.caption)
                                .foregroundStyle(.secondary)
                        }
                    } else {
                        HStack(spacing: 8) {
                            Button("Dismiss") { Task { await dismissItem(item) } }
                                .disabled(isBusy)
                            Button("Approve & Send") { Task { await approve(item) } }
                                .buttonStyle(.borderedProminent)
                                .disabled(isBusy)
                        }
                    }
                }

                VStack(alignment: .leading, spacing: 3) {
                    Text("Will notify \(item.targets.count):")
                        .font(.caption.weight(.medium))
                    ForEach(item.targets, id: \.address) { target in
                        HStack(alignment: .firstTextBaseline, spacing: 6) {
                            Text(target.address)
                                .font(.caption.monospaced())
                            Text(target.reason)
                                .font(.caption)
                                .foregroundStyle(.secondary)
                                .lineLimit(1)
                        }
                    }
                }

                DisclosureGroup("Redacted Header Evidence") {
                    ScrollView {
                        Text(item.redactedHeaders)
                            .font(.caption2.monospaced())
                            .textSelection(.enabled)
                            .frame(maxWidth: .infinity, alignment: .leading)
                    }
                    .frame(maxHeight: 140)
                    .padding(8)
                    .background(Color.secondary.opacity(0.08), in: RoundedRectangle(cornerRadius: 6))
                }
                .font(.caption)
            }
            .padding(6)
        }
    }

    private func historyRow(_ entry: AbuseHistoryEntry) -> some View {
        let delivered = entry.deliveries.filter(\.ok).count
        let replies = entry.replies ?? []
        let hasBan = replies.contains(where: { $0.outcome == "action_taken" })
        return GroupBox {
            VStack(alignment: .leading, spacing: 6) {
                HStack(spacing: 8) {
                    Text(entry.rootDomain)
                        .font(.headline)
                    switch entry.status {
                    case "sent": capsule("All \(delivered) delivered", color: .green)
                    case "partial": capsule("\(delivered) of \(entry.deliveries.count) delivered", color: .orange)
                    default: capsule("Failed, back in queue", color: .red)
                    }
                    if hasBan {
                        capsule("Banned", color: .green)
                    }
                    Spacer()
                    Text(formattedDate(entry.reportedAt))
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                if !entry.subject.isEmpty {
                    Text("Subject: \(entry.subject)")
                        .font(.callout)
                        .lineLimit(1)
                }
                ForEach(entry.deliveries, id: \.address) { d in
                    HStack(alignment: .firstTextBaseline, spacing: 6) {
                        Image(systemName: d.ok ? "checkmark.circle.fill" : "xmark.circle.fill")
                            .foregroundStyle(d.ok ? .green : .red)
                            .font(.caption)
                        Text(d.address)
                            .font(.caption.monospaced())
                        Text(d.ok ? d.reason : (d.error ?? "Failed"))
                            .font(.caption)
                            .foregroundStyle(d.ok ? Color.secondary : Color.red)
                            .lineLimit(2)
                    }
                }
                let notableReplies = replies.filter { $0.outcome != "acknowledged" }
                if !notableReplies.isEmpty {
                    Divider()
                    ForEach(notableReplies) { reply in
                        HStack(alignment: .firstTextBaseline, spacing: 6) {
                            Image(systemName: replyIcon(reply.outcome))
                                .foregroundStyle(replyColor(reply.outcome))
                                .font(.caption)
                            Text(replyLabel(reply.outcome))
                                .font(.caption.weight(.semibold))
                                .foregroundStyle(replyColor(reply.outcome))
                            Text(reply.snippet.isEmpty ? reply.responder : "\(reply.responder): \(reply.snippet)")
                                .font(.caption)
                                .foregroundStyle(.secondary)
                                .lineLimit(2)
                        }
                    }
                }
            }
            .padding(6)
            .frame(maxWidth: .infinity, alignment: .leading)
        }
    }

    private func replyIcon(_ outcome: String) -> String {
        switch outcome {
        case "action_taken": return "checkmark.shield.fill"
        case "form_only": return "hand.raised.fill"
        case "bounced": return "exclamationmark.circle.fill"
        default: return "envelope.fill"
        }
    }

    private func replyColor(_ outcome: String) -> Color {
        switch outcome {
        case "action_taken": return .green
        case "form_only": return .orange
        case "bounced": return .red
        default: return .secondary
        }
    }

    private func replyLabel(_ outcome: String) -> String {
        switch outcome {
        case "action_taken": return "Action taken"
        case "form_only": return "Web-form only (skipped)"
        case "bounced": return "Bounced"
        default: return "Replied"
        }
    }

    private func capsule(_ text: String, color: Color) -> some View {
        Text(text)
            .font(.caption.bold())
            .foregroundStyle(color == .secondary ? Color.primary : color)
            .padding(.horizontal, 6)
            .padding(.vertical, 2)
            .background(color.opacity(0.15), in: Capsule())
    }

    private func formattedDate(_ iso: String) -> String {
        guard let date = ISO8601DateFormatter().date(from: iso) else { return iso }
        return date.formatted(date: .abbreviated, time: .shortened)
    }

    private func refresh() async {
        await appState.refreshAbuseQueue()
        guard let client = appState.apiClient else { return }
        if let resp = try? await client.abuseHistory() {
            history = resp.entries
            bans = resp.bans ?? []
            formOnlyDomains = resp.formOnlyDomains ?? []
        }
    }

    private func syncReplies() async {
        guard let client = appState.apiClient else { return }
        isSyncingReplies = true
        defer { isSyncingReplies = false }
        do {
            let res = try await client.syncAbuseReplies()
            errorMessage = nil
            syncStatus = "Checked \(res.processed), archived \(res.archived)"
            await appState.refreshAll()
            await refresh()
        } catch {
            errorMessage = "Could not check replies: \(error.localizedDescription)"
        }
    }

    private func removeFormOnlyDomain(_ domain: String) async {
        guard let client = appState.apiClient else { return }
        do {
            try await client.deleteFormOnlyDomain(domain)
            errorMessage = nil
            await refresh()
        } catch {
            errorMessage = "Could not remove \(domain): \(error.localizedDescription)"
        }
    }

    private func approve(_ item: AbuseQueueItem) async {
        guard let client = appState.apiClient else { return }
        busyIDs.insert(item.id)
        defer { busyIDs.remove(item.id) }
        do {
            try await client.approveAbuse(id: item.id)
            errorMessage = nil
            await refresh()
        } catch {
            errorMessage = "Could not start sending: \(error.localizedDescription)"
        }
    }

    private func dismissItem(_ item: AbuseQueueItem) async {
        guard let client = appState.apiClient else { return }
        busyIDs.insert(item.id)
        defer { busyIDs.remove(item.id) }
        do {
            try await client.dismissAbuse(id: item.id)
            errorMessage = nil
            await refresh()
        } catch {
            errorMessage = "Could not dismiss: \(error.localizedDescription)"
        }
    }
}
