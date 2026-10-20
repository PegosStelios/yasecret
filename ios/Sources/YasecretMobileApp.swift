import SwiftUI

@main
struct YasecretMobileApp: App {
    @State private var state = MobileState()

    var body: some Scene {
        WindowGroup {
            Group {
                if let session = state.session {
                    ProjectsView(session: session)
                } else {
                    UnlockView()
                }
            }
            .environment(state)
            .onOpenURL { url in
                if url.scheme == "yasecret" { state.pendingJoinLink = url.absoluteString }
            }
        }
    }
}
