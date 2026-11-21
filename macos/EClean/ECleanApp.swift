import SwiftUI

@main
struct ECleanApp: App {
    @State private var appState = AppState()

    var body: some Scene {
        WindowGroup {
            Group {
                if appState.connection == nil {
                    OnboardingView()
                } else {
                    MainTabView()
                }
            }
            .environment(appState)
            .frame(minWidth: 780, minHeight: 540)
            .sheet(item: $appState.incomingPairRequest) { request in
                PairingApprovalSheet(request: request)
                    .environment(appState)
            }
            .task {
                await appState.bootstrap()
            }
        }
        .defaultSize(width: 920, height: 640)
        .commands {
            CommandGroup(replacing: .appSettings) {
                Button("Settings...") {
                    appState.showSettings = true
                }
                .keyboardShortcut(",", modifiers: .command)
                .disabled(appState.connection == nil)
            }
        }
    }
}
