import SwiftUI

struct AbuseReviewSheet: View {
    @Environment(AppState.self) private var appState
    @Environment(\.dismiss) private var dismiss

    private enum Tab: String, CaseIterable, Identifiable {
        case queue = "Waiting for Approval"
        case sent = "Sent Reports"
        var id: String { rawValue }
    }

    @State private var tab: Tab = .queue
    @State private var history: [AbuseHistoryEntry] = []
    @State private var busyIDs: Set<Int64> = []
    @State private var errorMessage: String?

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
        if history.isEmpty {
            emptyState(icon: "paperplane", title: "No reports sent yet", detail: "Approved reports show here with the result for every recipient.")
        } else {
            ScrollView {
                VStack(spacing: 12) {
                    ForEach(history) { historyRow($0) }
                }
                .padding(18)
            }
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
            }
            .padding(6)
            .frame(maxWidth: .infinity, alignment: .leading)
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
        if let entries = try? await client.abuseHistory() {
            history = entries
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
