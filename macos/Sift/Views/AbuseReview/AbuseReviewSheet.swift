import SwiftUI

struct AbuseReviewSheet: View {
    @Environment(AppState.self) private var appState
    @Environment(\.dismiss) private var dismiss

    @State private var busyIDs: Set<Int64> = []
    @State private var statusBanner: String?

    var body: some View {
        VStack(spacing: 0) {
            HStack {
                Image(systemName: "exclamationmark.triangle.fill")
                    .foregroundStyle(.yellow)
                Text("Domains Queued for Abuse Reporting")
                    .font(.title3.bold())
                Spacer()
                Button("Done") { dismiss() }
                    .keyboardShortcut(.cancelAction)
            }
            .padding(.horizontal, 20)
            .padding(.vertical, 14)

            Divider()

            if let statusBanner {
                HStack {
                    Text(statusBanner)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                    Spacer()
                }
                .padding(.horizontal, 20)
                .padding(.vertical, 8)
                Divider()
            }

            if appState.abuseQueue.isEmpty {
                VStack(spacing: 10) {
                    Image(systemName: "checkmark.seal.fill")
                        .font(.system(size: 36))
                        .foregroundStyle(.green)
                    Text("No domains waiting for review")
                        .font(.headline)
                    Text("High-confidence spam domains eligible for abuse reporting will appear here.")
                        .font(.callout)
                        .foregroundStyle(.secondary)
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                ScrollView {
                    VStack(spacing: 12) {
                        ForEach(appState.abuseQueue) { item in
                            queueRow(item)
                        }
                    }
                    .padding(18)
                }
            }
        }
        .frame(width: 680, height: 520)
        .task {
            await appState.refreshAbuseQueue()
        }
    }

    private func queueRow(_ item: AbuseQueueItem) -> some View {
        let isBusy = busyIDs.contains(item.id)
        return GroupBox {
            VStack(alignment: .leading, spacing: 8) {
                HStack(alignment: .top) {
                    VStack(alignment: .leading, spacing: 4) {
                        HStack(spacing: 8) {
                            Text(item.rootDomain)
                                .font(.headline)
                            Text("\(item.hitCount) \(item.hitCount == 1 ? "email" : "emails")")
                                .font(.caption.bold())
                                .padding(.horizontal, 6)
                                .padding(.vertical, 2)
                                .background(Color.secondary.opacity(0.15), in: Capsule())
                            if item.repeatOffense {
                                Text("Repeat Offense")
                                    .font(.caption.bold())
                                    .foregroundStyle(.orange)
                                    .padding(.horizontal, 6)
                                    .padding(.vertical, 2)
                                    .background(Color.orange.opacity(0.15), in: Capsule())
                            }
                        }

                        Text("Subject: \(item.subject.isEmpty ? "(No subject)" : item.subject)")
                            .font(.callout)
                            .lineLimit(1)

                        Text("Category: \(item.categoryID) (\(Int(item.confidence * 100))%) · IP: \(item.sendingIP.isEmpty ? "Unknown" : item.sendingIP)")
                            .font(.caption)
                            .foregroundStyle(.secondary)

                        if item.repeatOffense, let prev = item.previousReportedAt, !prev.isEmpty {
                            Text("Previously reported on \(prev)")
                                .font(.caption)
                                .foregroundStyle(.orange)
                        }

                        Text("Will notify: \(item.targets.joined(separator: ", "))")
                            .font(.caption.monospaced())
                            .foregroundStyle(.secondary)
                    }
                    Spacer()
                    HStack(spacing: 8) {
                        Button("Dismiss") {
                            Task { await dismissItem(item) }
                        }
                        .disabled(isBusy)

                        Button(isBusy ? "Sending..." : "Approve & Send") {
                            Task { await approveItem(item) }
                        }
                        .buttonStyle(.borderedProminent)
                        .disabled(isBusy)
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

    private func approveItem(_ item: AbuseQueueItem) async {
        guard let client = appState.apiClient else { return }
        busyIDs.insert(item.id)
        defer { busyIDs.remove(item.id) }
        do {
            let res = try await client.approveAbuse(id: item.id)
            if res.status == "sent" {
                statusBanner = "Sent abuse report for \(item.rootDomain)."
            } else {
                statusBanner = "Report failed for \(item.rootDomain): \(res.error)"
            }
            await appState.refreshAbuseQueue()
        } catch {
            statusBanner = "Error sending report: \(error.localizedDescription)"
        }
    }

    private func dismissItem(_ item: AbuseQueueItem) async {
        guard let client = appState.apiClient else { return }
        busyIDs.insert(item.id)
        defer { busyIDs.remove(item.id) }
        do {
            try await client.dismissAbuse(id: item.id)
            statusBanner = "Dismissed \(item.rootDomain) from future abuse reporting."
            await appState.refreshAbuseQueue()
        } catch {
            statusBanner = "Error dismissing domain: \(error.localizedDescription)"
        }
    }
}
