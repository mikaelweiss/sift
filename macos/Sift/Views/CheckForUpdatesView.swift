import Sparkle
import SwiftUI

@Observable
final class CheckForUpdatesViewModel {
    var canCheckForUpdates = false
    @ObservationIgnored private var observation: NSKeyValueObservation?

    init(updater: SPUUpdater) {
        observation = updater.observe(\.canCheckForUpdates, options: [.initial, .new]) { [weak self] _, change in
            self?.canCheckForUpdates = change.newValue ?? false
        }
    }
}

struct CheckForUpdatesView: View {
    let updater: SPUUpdater
    @State private var viewModel: CheckForUpdatesViewModel

    init(updater: SPUUpdater) {
        self.updater = updater
        self._viewModel = State(wrappedValue: CheckForUpdatesViewModel(updater: updater))
    }

    var body: some View {
        Button("Check for Updates…", action: updater.checkForUpdates)
            .disabled(!viewModel.canCheckForUpdates)
    }
}
