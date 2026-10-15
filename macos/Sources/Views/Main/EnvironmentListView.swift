import SwiftUI

struct EnvironmentListView: View {
    @Environment(AppState.self) private var appState
    @Bindable var vm: EnvironmentsViewModel
    let projectId: String
    @State private var showingNew = false
    @State private var newName = ""
    @State private var renamingId: String?
    @State private var renameText = ""

    var body: some View {
        List(vm.environments, id: \.id, selection: Bindable(vm).selectedEnvId) { env in
            if renamingId == env.id {
                TextField("Environment name", text: $renameText, onCommit: commitRename)
                    .textFieldStyle(.plain)
                    .onExitCommand { renamingId = nil }
            } else {
                Text(env.name).tag(env.id)
                    .contextMenu {
                        Button("Rename…") {
                            renamingId = env.id
                            renameText = env.name
                        }
                        Divider()
                        Button("Delete", role: .destructive) {
                            guard let session = appState.session else { return }
                            vm.deleteEnvironment(id: env.id, session: session)
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
                    Label("New Environment", systemImage: "plus")
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
                Text("New Environment").font(.headline)
                TextField("Environment name", text: $newName)
                    .textFieldStyle(.roundedBorder)
                    .frame(width: 220)
                    .onSubmit { createEnvironment() }
                HStack {
                    Button("Cancel") { showingNew = false; newName = "" }
                    Button("Create") { createEnvironment() }
                        .buttonStyle(.borderedProminent)
                        .disabled(newName.isEmpty)
                }
            }
            .padding(24)
        }
    }

    private func createEnvironment() {
        guard let session = appState.session, !newName.isEmpty else { return }
        vm.createEnvironment(projectId: projectId, name: newName, session: session)
        newName = ""; showingNew = false
    }

    private func commitRename() {
        guard let id = renamingId, let session = appState.session,
              !renameText.isEmpty, renameText != vm.environments.first(where: { $0.id == id })?.name
        else { renamingId = nil; return }
        vm.renameEnvironment(id: id, newName: renameText, session: session)
        renamingId = nil
    }
}
