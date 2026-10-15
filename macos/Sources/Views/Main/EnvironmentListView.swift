import SwiftUI

struct EnvironmentListView: View {
    @Environment(AppState.self) private var appState
    @Bindable var vm: EnvironmentsViewModel
    let projectId: String
    @State private var showingNew = false
    @State private var newName = ""

    var body: some View {
        List(vm.environments, id: \.id, selection: Bindable(vm).selectedEnvId) { env in
            Text(env.name).tag(env.id)
                .contextMenu {
                    Button("Delete", role: .destructive) {
                        guard let session = appState.session else { return }
                        vm.deleteEnvironment(id: env.id, session: session)
                    }
                }
        }
        .toolbar {
            ToolbarItem(placement: .primaryAction) {
                Button { showingNew = true } label: { Image(systemName: "plus") }
            }
        }
        .sheet(isPresented: $showingNew) {
            VStack(spacing: 16) {
                TextField("Environment name", text: $newName)
                    .textFieldStyle(.roundedBorder).frame(width: 220)
                HStack {
                    Button("Cancel") { showingNew = false }
                    Button("Create") {
                        guard let session = appState.session, !newName.isEmpty else { return }
                        vm.createEnvironment(projectId: projectId, name: newName, session: session)
                        newName = ""; showingNew = false
                    }.buttonStyle(.borderedProminent)
                }
            }.padding(24)
        }
    }
}
