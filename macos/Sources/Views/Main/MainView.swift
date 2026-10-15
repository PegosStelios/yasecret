import SwiftUI

struct MainView: View {
    @Environment(AppState.self) private var appState
    @State private var projectsVM = ProjectsViewModel()
    @State private var envsVM = EnvironmentsViewModel()
    @State private var secretsVM = SecretsViewModel()

    var body: some View {
        NavigationSplitView {
            ProjectListView(vm: projectsVM)
                .navigationTitle("Projects")
        } content: {
            if let projId = projectsVM.selectedProjectId {
                EnvironmentListView(vm: envsVM, projectId: projId)
                    .navigationTitle("Environments")
            } else {
                ContentUnavailableView("Select a project", systemImage: "folder")
            }
        } detail: {
            if let envId = envsVM.selectedEnvId,
               let projId = projectsVM.selectedProjectId {
                SecretListView(vm: secretsVM, projectId: projId, envId: envId)
                    .navigationTitle("Secrets")
            } else {
                ContentUnavailableView("Select an environment", systemImage: "list.bullet.rectangle")
            }
        }
        .frame(minWidth: 900, minHeight: 500)
        .task {
            guard let session = appState.session else { return }
            projectsVM.load(session: session)
        }
        .onChange(of: projectsVM.selectedProjectId) { _, projId in
            guard let projId, let session = appState.session else { return }
            envsVM.selectedEnvId = nil
            envsVM.load(projectId: projId, session: session)
        }
        .onChange(of: envsVM.selectedEnvId) { _, envId in
            guard let envId, let session = appState.session else { return }
            secretsVM.load(envId: envId, session: session)
        }
    }
}
