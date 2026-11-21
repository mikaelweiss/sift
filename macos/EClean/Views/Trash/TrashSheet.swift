import SwiftUI

struct TrashSheet: View {
    @Environment(AppState.self) private var appState
    @Environment(\.dismiss) private var dismiss

    @State private var listing: TrashListing?
    @State private var selection: Set<UInt32> = []
    @State private var isLoading = false
    @State private var isDeleting = false
    @State private var errorMessage: String?
    @State private var statusBanner: String?
    @State private var pendingDelete: [UInt32] = []

    var body: some View {
        VStack(spacing: 0) {
            HStack {
                Image(systemName: "trash.fill")
                    .foregroundStyle(.secondary)
                VStack(alignment: .leading, spacing: 2) {
                    Text("Spam in Trash")
                        .font(.title3.bold())
                    Text("Only mail EClean moved to Trash. Mail you trashed yourself is never shown or deleted here.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                Spacer()
                Button {
                    Task { await load() }
                } label: {
                    Image(systemName: "arrow.clockwise")
                }
                .disabled(isLoading || isDeleting)
                .help("Reload")
                Button("Done") { dismiss() }
                    .keyboardShortcut(.cancelAction)
            }
            .padding(.horizontal, 20)
            .padding(.vertical, 14)

            Divider()

            if let banner = errorMessage ?? statusBanner {
                HStack {
                    Text(banner)
                        .font(.caption)
                        .foregroundStyle(errorMessage == nil ? Color.secondary : Color.red)
                    Spacer()
                }
                .padding(.horizontal, 20)
                .padding(.vertical, 8)
                Divider()
            }

            content
                .frame(maxWidth: .infinity, maxHeight: .infinity)

            if let items = listing?.items, !items.isEmpty {
                Divider()
                HStack {
                    Text(selection.isEmpty ? "\(items.count) \(items.count == 1 ? "email" : "emails")" : "\(selection.count) selected")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                    Spacer()
                    if isDeleting {
                        ProgressView().controlSize(.small)
                    }
                    Button("Delete Selected") {
                        pendingDelete = Array(selection)
                    }
                    .disabled(selection.isEmpty || isDeleting)
                    Button("Delete All \(items.count)", role: .destructive) {
                        pendingDelete = items.map(\.uid)
                    }
                    .buttonStyle(.borderedProminent)
                    .tint(.red)
                    .disabled(isDeleting)
                }
                .padding(.horizontal, 20)
                .padding(.vertical, 12)
            }
        }
        .frame(width: 680, height: 520)
        .task { await load() }
        .confirmationDialog(
            "Permanently delete \(pendingDelete.count) \(pendingDelete.count == 1 ? "email" : "emails")?",
            isPresented: Binding(get: { !pendingDelete.isEmpty }, set: { if !$0 { pendingDelete = [] } })
        ) {
            Button("Delete Permanently", role: .destructive) {
                let uids = pendingDelete
                Task { await delete(uids) }
            }
        } message: {
            Text("They are removed from iCloud and cannot be recovered.")
        }
    }

    @ViewBuilder
    private var content: some View {
        if let items = listing?.items {
            if items.isEmpty {
                VStack(spacing: 10) {
                    Image(systemName: "checkmark.seal.fill")
                        .font(.system(size: 36))
                        .foregroundStyle(.green)
                    Text("No spam waiting in Trash")
                        .font(.headline)
                }
            } else {
                List(items, selection: $selection) { item in
                    row(item)
                }
            }
        } else if isLoading {
            ProgressView("Reading Trash...")
        }
    }

    private func row(_ item: TrashItem) -> some View {
        HStack {
            VStack(alignment: .leading, spacing: 2) {
                Text(item.subject.isEmpty ? "(No subject)" : item.subject)
                    .font(.callout.weight(.medium))
                    .lineLimit(1)
                Text(item.sender)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
            }
            Spacer()
            Text("\(item.categoryID) · \(Int(item.confidence * 100))%")
                .font(.caption2.monospacedDigit())
                .padding(.horizontal, 6)
                .padding(.vertical, 2)
                .background(Color.orange.opacity(0.15), in: Capsule())
        }
        .padding(.vertical, 2)
    }

    private func load() async {
        guard let client = appState.apiClient else { return }
        isLoading = true
        defer { isLoading = false }
        do {
            listing = try await client.listTrash()
            selection = selection.intersection(Set(listing?.items.map(\.uid) ?? []))
            errorMessage = nil
        } catch {
            errorMessage = "Could not read Trash: \(error.localizedDescription)"
        }
    }

    private func delete(_ uids: [UInt32]) async {
        guard let client = appState.apiClient, let listing else { return }
        isDeleting = true
        defer { isDeleting = false }
        do {
            let deleted = try await client.deleteFromTrash(uidValidity: listing.uidValidity, uids: uids)
            statusBanner = "Permanently deleted \(deleted) \(deleted == 1 ? "email" : "emails")."
            errorMessage = nil
            selection.subtract(uids)
            await load()
            await appState.refreshStats(days: appState.selectedStatsDays)
        } catch {
            errorMessage = "Delete failed: \(error.localizedDescription)"
        }
    }
}
