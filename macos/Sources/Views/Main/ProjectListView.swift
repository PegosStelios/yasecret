import SwiftUI

struct ProjectListView: View {
    @Environment(AppState.self) private var appState
    @Bindable var vm: ProjectsViewModel
    @State private var showingNew = false
    @State private var newName = ""

    var body: some View {
        List(vm.projects, id: \.id, selection: Bindable(vm).selectedProjectId) { proj in
            Text(proj.name)
                .tag(proj.id)
                .contextMenu {
                    Button("Delete", role: .destructive) {
                        guard let session = appState.session else { return }
                        vm.deleteProject(id: proj.id, session: session)
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
                TextField("Project name", text: $newName)
                    .textFieldStyle(.roundedBorder).frame(width: 240)
                HStack {
                    Button("Cancel") { showingNew = false }
                    Button("Create") {
                        guard let session = appState.session, !newName.isEmpty else { return }
                        vm.createProject(name: newName, session: session)
                        newName = ""; showingNew = false
                    }.buttonStyle(.borderedProminent)
                }
            }.padding(24)
        }
    }
}
