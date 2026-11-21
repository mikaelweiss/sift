import SwiftUI

struct MainTabView: View {
    @Environment(AppState.self) private var appState
    @State private var showAbuseReview = false
    @State private var showTrash = false

    var body: some View {
        @Bindable var bindableState = appState
        let hasQueuedDomains = !appState.abuseQueue.isEmpty

        NavigationStack {
            HomeView()
                .navigationTitle("Sift")
                .toolbar {
                    ToolbarItem(placement: .navigation) {
                        Button {
                            Task { await appState.reconnect() }
                        } label: {
                            HStack(spacing: 6) {
                                if appState.isReconnecting {
                                    ProgressView().controlSize(.mini)
                                } else {
                                    Circle()
                                        .fill(statusColor)
                                        .frame(width: 7, height: 7)
                                }
                                Text(statusText)
                                    .font(.caption)
                                    .foregroundStyle(.secondary)
                                if !appState.isConnected || appState.health?.imapConnected != true {
                                    Image(systemName: "arrow.clockwise")
                                        .font(.caption2)
                                        .foregroundStyle(.secondary)
                                }
                            }
                            .padding(.horizontal, 8)
                        }
                        .buttonStyle(.plain)
                        .help(statusTooltip)
                    }

                    ToolbarItemGroup(placement: .primaryAction) {
                        Button {
                            showAbuseReview = true
                        } label: {
                            if hasQueuedDomains {
                                HStack(spacing: 4) {
                                    Image(systemName: "exclamationmark.triangle.fill")
                                        .foregroundStyle(.yellow)
                                    Text("\(appState.abuseQueue.count)")
                                        .font(.caption.bold().monospacedDigit())
                                        .padding(.horizontal, 5)
                                        .padding(.vertical, 1)
                                        .background(Color.yellow.opacity(0.25), in: Capsule())
                                }
                            } else {
                                Image(systemName: "exclamationmark.triangle")
                                    .foregroundStyle(.secondary)
                            }
                        }
                        .disabled(!hasQueuedDomains)
                        .help(hasQueuedDomains ? "Review domains queued for abuse reporting" : "No domains queued for abuse reporting")

                        Button {
                            showTrash = true
                        } label: {
                            Image(systemName: "trash")
                        }
                        .help("Review spam in Trash and delete it permanently")

                        Button {
                            appState.showSettings = true
                        } label: {
                            Image(systemName: "gearshape")
                        }
                        .help("Settings (⌘,)")
                    }
                }
                .sheet(isPresented: $showAbuseReview) {
                    AbuseReviewSheet()
                        .environment(appState)
                }
                .sheet(isPresented: $showTrash) {
                    TrashSheet()
                        .environment(appState)
                }
                .sheet(isPresented: $bindableState.showSettings) {
                    SettingsSheet()
                        .environment(appState)
                }
        }
    }

    private var statusColor: Color {
        guard appState.isConnected else { return .red }
        if appState.health?.imapConnected == true { return .green }
        return .orange
    }

    private var statusText: String {
        guard appState.isConnected else { return "Offline · Reconnect" }
        let host = appState.connection?.host.components(separatedBy: ".").first ?? "Server"
        if appState.health?.imapConnected == true {
            return "\(host) · Active"
        }
        return "\(host) · IMAP Reconnecting"
    }

    private var statusTooltip: String {
        if !appState.isConnected {
            return "Server offline. Click to reconnect."
        }
        if let err = appState.health?.imapError, !err.isEmpty {
            return "IMAP status: \(err). Click to refresh."
        }
        return "Connected. Click to refresh."
    }
}
