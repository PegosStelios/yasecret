import SwiftUI

@main
struct YasecretApp: App {
    @State private var appState = AppState()

    var body: some Scene {
        WindowGroup {
            LoadingView()
                .environment(appState)
        }
        .windowStyle(.hiddenTitleBar)
        .commands {
            CommandGroup(replacing: .newItem) {}
        }
    }
}
