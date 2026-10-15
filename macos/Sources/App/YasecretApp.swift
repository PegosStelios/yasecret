import SwiftUI

@main
struct YasecretApp: App {
    @State private var appState = AppState()

    var body: some Scene {
        WindowGroup {
            if appState.isLocked {
                UnlockView()
                    .environment(appState)
            } else {
                MainView()
                    .environment(appState)
            }
        }
        .windowStyle(.hiddenTitleBar)
        .commands {
            CommandGroup(replacing: .newItem) {}
            CommandGroup(after: .appInfo) {
                Button("Lock Vault") { appState.lock() }
                    .disabled(appState.isLocked)
                .keyboardShortcut("l", modifiers: [.command, .shift])
            }
        }
    }
}
