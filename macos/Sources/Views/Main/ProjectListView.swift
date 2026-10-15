import SwiftUI

struct ProjectListView: View {
    @Environment(AppState.self) private var appState
    @Bindable var vm: ProjectsViewModel
    @State private var showingNew = false
    @State private var newName = ""
    @State private var renamingId: String?
    @State private var renameText = ""

    var body: some View {
        List(vm.projects, id: \.id, selection: Bindable(vm).selectedProjectId) { proj in
            if renamingId == proj.id {
                TextField("Project name", text: $renameText, onCommit: commitRename)
                    .textFieldStyle(.plain)
                    .onExitCommand { renamingId = nil }
            } else {
                Text(proj.name)
                    .tag(proj.id)
                    .contextMenu {
                        Button("Rename…") {
                            renamingId = proj.id
                            renameText = proj.name
                        }
                        Divider()
                        Button("Delete", role: .destructive) {
                            guard let session = appState.session else { return }
                            vm.deleteProject(id: proj.id, session: session)
                        }
                    }
            }
        }
        .safeAreaInset(edge: .bottom, spacing: 0) {
            VStack(spacing: 0) {
                Divider()
                Button {
                    showingNew = true
                } label: {
                    Label("New Project", systemImage: "plus")
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .padding(.horizontal, 14)
                        .padding(.vertical, 9)
                }
                .buttonStyle(.plain)
                .foregroundStyle(.secondary)
            }
            .background(.regularMaterial)
        }
        .sheet(isPresented: $showingNew) {
            VStack(spacing: 16) {
                Text("New Project").font(.headline)
                TextField("Project name", text: $newName)
                    .textFieldStyle(.roundedBorder)
                    .frame(width: 240)
                    .onSubmit { createProject() }
                HStack {
                    Button("Cancel") { showingNew = false; newName = "" }
                    Button("Create") { createProject() }
                        .buttonStyle(.borderedProminent)
                        .disabled(newName.isEmpty)
                }
            }
            .padding(24)
        }
    }

    private func createProject() {
        guard let session = appState.session, !newName.isEmpty else { return }
        vm.createProject(name: newName, session: session)
        newName = ""; showingNew = false
    }

    private func commitRename() {
        guard let id = renamingId, let session = appState.session,
              !renameText.isEmpty, renameText != vm.projects.first(where: { $0.id == id })?.name
        else { renamingId = nil; return }
        vm.renameProject(id: id, newName: renameText, session: session)
        renamingId = nil
    }
}
