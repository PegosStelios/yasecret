import SwiftUI
import AppKit

struct SecretListView: View {
    @Environment(AppState.self) private var appState
    @Bindable var vm: SecretsViewModel
    let projectId: String
    let envId: String
    @State private var showingNew = false
    @State private var showingImport = false
    @State private var selectedIds: Set<String> = []

    var body: some View {
        List(vm.secrets, id: \.id, selection: $selectedIds) { secret in
            if let session = appState.session {
                SecretRowView(secret: secret, projectId: projectId, session: session)
                    .tag(secret.id)
            }
        }
        .toolbar {
            ToolbarItem(placement: .primaryAction) {
                Button { showingNew = true } label: { Image(systemName: "plus") }
                    .disabled(appState.session == nil)
            }
            ToolbarItem(placement: .status) {
                Text("\(vm.secrets.count) secret\(vm.secrets.count == 1 ? "" : "s")")
                    .foregroundStyle(.secondary)
            }
            ToolbarItemGroup(placement: .secondaryAction) {
                Button {
                    showingImport = true
                } label: {
                    Label("Import .env", systemImage: "square.and.arrow.down")
                }
                .disabled(appState.session == nil)

                Button {
                    guard let session = appState.session else { return }
                    if let exported = try? session.exportEnv(projectId: projectId, envId: envId) {
                        let panel = NSSavePanel()
                        panel.nameFieldStringValue = ".env"
                        if panel.runModal() == .OK, let url = panel.url {
                            try? exported.write(to: url, atomically: true, encoding: .utf8)
                        }
                    }
                } label: {
                    Label("Export .env", systemImage: "square.and.arrow.up")
                }
                .disabled(appState.session == nil || vm.secrets.isEmpty)
            }
        }
        .contextMenu(forSelectionType: String.self) { ids in
            Button("Delete", role: .destructive) {
                guard let session = appState.session else { return }
                ids.forEach { vm.deleteSecret(id: $0, session: session) }
            }
        }
        .sheet(isPresented: $showingNew) {
            if let session = appState.session {
                NewSecretView(projectId: projectId, envId: envId, vm: vm, session: session)
            }
        }
        .sheet(isPresented: $showingImport) {
            if let session = appState.session {
                ImportEnvView(projectId: projectId, envId: envId, session: session) { _ in
                    vm.load(envId: envId, session: session)
                }
            }
        }
    }
}
