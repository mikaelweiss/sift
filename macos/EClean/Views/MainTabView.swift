import SwiftUI

private enum AppTab: Hashable {
    case home
    case features
}

struct MainTabView: View {
    @Environment(AppState.self) private var appState
    @State private var selectedTab: AppTab = .home
    @State private var showSettings = false
    @State private var showAbuseReview = false

    var body: some View {
        NavigationStack {
            TabView(selection: $selectedTab) {
                HomeView()
                    .tabItem {
                        Label("Home", systemImage: "chart.bar.xaxis")
                    }
                    .tag(AppTab.home)

                FeaturesView()
                    .tabItem {
                        Label("Features", systemImage: "sparkles")
                    }
                    .tag(AppTab.features)
            }
            .padding(.top, 8)
            .toolbar {
                ToolbarItemGroup(placement: .primaryAction) {
                    Button {
                        showAbuseReview = true
                    } label: {
                        HStack(spacing: 4) {
                            Image(systemName: "exclamationmark.triangle.fill")
                                .foregroundStyle(.yellow)
                            if !appState.abuseQueue.isEmpty {
                                Text("\(appState.abuseQueue.count)")
                                    .font(.caption.bold().monospacedDigit())
                                    .padding(.horizontal, 5)
                                    .padding(.vertical, 1)
                                    .background(Color.yellow.opacity(0.25), in: Capsule())
                            }
                        }
                    }
                    .help("Review domains queued for abuse reporting")

                    Button {
                        showSettings = true
                    } label: {
                        Image(systemName: "gearshape")
                    }
                    .help("Settings")
                }
            }
            .sheet(isPresented: $showAbuseReview) {
                AbuseReviewSheet()
                    .environment(appState)
            }
            .sheet(isPresented: $showSettings) {
                SettingsSheet()
                    .environment(appState)
            }
        }
    }
}
