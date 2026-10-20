import SwiftUI

@main
struct YasecretApp: App {
    @State private var appState = AppState()

    var body: some Scene {
        WindowGroup {
            Group {
                if appState.isLocked {
                    UnlockView()
                } else {
                    MainView()
                }
            }
            .environment(appState)
            .onOpenURL { url in
                if url.scheme == "yasecret" { appState.pendingJoinLink = url.absoluteString }
            }
        }
        .windowStyle(.hiddenTitleBar)
        .handlesExternalEvents(matching: ["join"])
        .commands {
            CommandGroup(replacing: .newItem) {}
            CommandGroup(after: .appInfo) {
                Button("Lock Vault") { appState.lock() }
                    .disabled(appState.isLocked)
                .keyboardShortcut("l", modifiers: [.command, .shift])
            }
            CommandMenu("Vault") {
                Button("Change Master Password…") { appState.vaultSheet = .changePassword }
                    .disabled(appState.isLocked)
                Button("Recovery Key…") { appState.vaultSheet = .recoveryKey }
                    .disabled(appState.isLocked)
                Divider()
                Button("Back Up Vault…") { appState.backUp() }
                    .disabled(appState.isLocked)
            }
        }
    }
}
