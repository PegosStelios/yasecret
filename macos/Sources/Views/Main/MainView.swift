import SwiftUI

struct MainView: View {
    @Environment(AppState.self) private var appState
    var body: some View {
        Text("Main — coming in Task 4")
            .frame(width: 900, height: 600)
    }
}
