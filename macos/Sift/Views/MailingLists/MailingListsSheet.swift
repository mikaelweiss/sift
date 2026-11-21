import SwiftUI

struct MailingListsSheet: View {
    @Environment(AppState.self) private var appState
    @Environment(\.dismiss) private var dismiss

    @State private var lists: [MailingList]?
    @State private var busySenders: Set<String> = []
    @State private var errorMessage: String?

    var body: some View {
        VStack(spacing: 0) {
            HStack {
                Image(systemName: "envelope.open.fill")
                    .foregroundStyle(.secondary)
                VStack(alignment: .leading, spacing: 2) {
                    Text("Mailing Lists")
                        .font(.title3.bold())
                    Text("Only senders that pass email authentication, support one-click unsubscribe, have never sent you scam or adult mail, and have emailed you for at least 30 days.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
                Spacer()
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

            content
                .frame(maxWidth: .infinity, maxHeight: .infinity)
        }
        .frame(width: 680, height: 520)
        .task { await load() }
    }

    @ViewBuilder
    private var content: some View {
        if let lists {
            if lists.isEmpty {
                VStack(spacing: 10) {
                    Image(systemName: "tray")
                        .font(.system(size: 36))
                        .foregroundStyle(.secondary)
                    Text("No mailing lists found yet")
                        .font(.headline)
                    Text("Run a scan so Sift can see which senders qualify.")
                        .font(.callout)
                        .foregroundStyle(.secondary)
                }
            } else {
                List(lists) { list in
                    row(list)
                }
            }
        } else {
            ProgressView("Loading mailing lists...")
        }
    }

    private func row(_ list: MailingList) -> some View {
        HStack(spacing: 12) {
            VStack(alignment: .leading, spacing: 2) {
                Text(list.displayName.isEmpty ? list.sender : list.displayName)
                    .font(.callout.weight(.medium))
                    .lineLimit(1)
                Text("\(list.sender) · since \(String(list.firstSeen.prefix(10)))")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
                if !list.lastSubject.isEmpty {
                    Text(list.lastSubject)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                }
                if let error = list.error, !error.isEmpty {
                    Text("Unsubscribe failed: \(error)")
                        .font(.caption)
                        .foregroundStyle(.red)
                        .lineLimit(2)
                }
            }
            Spacer()
            if let done = list.unsubscribedAt, !done.isEmpty {
                Label("Unsubscribed", systemImage: "checkmark.circle.fill")
                    .font(.caption)
                    .foregroundStyle(.green)
            } else if busySenders.contains(list.sender) {
                ProgressView().controlSize(.small)
            } else {
                Button(list.error?.isEmpty == false ? "Retry" : "Unsubscribe") {
                    Task { await unsubscribe(list) }
                }
            }
        }
        .padding(.vertical, 3)
    }

    private func load() async {
        guard let client = appState.apiClient else { return }
        do {
            lists = try await client.listMailingLists()
            errorMessage = nil
        } catch {
            errorMessage = "Could not load mailing lists: \(error.localizedDescription)"
        }
    }

    private func unsubscribe(_ list: MailingList) async {
        guard let client = appState.apiClient else { return }
        busySenders.insert(list.sender)
        defer { busySenders.remove(list.sender) }
        do {
            let updated = try await client.unsubscribe(sender: list.sender)
            if let index = lists?.firstIndex(where: { $0.sender == updated.sender }) {
                lists?[index] = updated
            }
            errorMessage = nil
        } catch {
            errorMessage = "Unsubscribe failed: \(error.localizedDescription)"
        }
    }
}
