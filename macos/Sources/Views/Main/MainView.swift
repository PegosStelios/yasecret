import SwiftUI

struct MainView: View {
    @Environment(AppState.self) private var appState
    @State private var projectsVM = ProjectsViewModel()
    @State private var envsVM = EnvironmentsViewModel()
    @State private var secretsVM = SecretsViewModel()

    var body: some View {
        NavigationSplitView {
            ProjectListView(vm: projectsVM)
                .navigationSplitViewColumnWidth(min: 180, ideal: 210, max: 280)
        } content: {
            Group {
                if let proj = selectedProject {
                    EnvironmentListView(vm: envsVM, projectId: proj.id, projectName: proj.name)
                } else {
                    ContentUnavailableView("Select a project", systemImage: "folder",
                                           description: Text("Pick a project on the left, or create one."))
                }
            }
            .navigationSplitViewColumnWidth(min: 180, ideal: 210, max: 280)
        } detail: {
            if let env = envsVM.selectedEnvironment, let proj = selectedProject {
                SecretListView(vm: secretsVM, projectId: proj.id, envId: env.id, envName: env.name,
                               onChanged: refreshEnvironmentCounts)
                    .id(env.id)
            } else {
                ContentUnavailableView("Select an environment", systemImage: "list.bullet.rectangle")
            }
        }
        .frame(minWidth: 1040, minHeight: 560)
        .task {
            guard let session = appState.session else { return }
            projectsVM.load(session: session)
            if projectsVM.selectedProjectId == nil {
                projectsVM.selectedProjectId = projectsVM.projects.first?.id
            }
        }
        .onChange(of: projectsVM.selectedProjectId) { _, projId in
            envsVM.selectedEnvId = nil
            envsVM.environments = []
            guard let projId, let session = appState.session else { return }
            envsVM.load(projectId: projId, session: session)
        }
        .onChange(of: envsVM.selectedEnvId) { _, envId in
            secretsVM.searchText = ""
            secretsVM.secrets = []
            guard let envId, let session = appState.session else { return }
            secretsVM.load(envId: envId, session: session)
        }
    }

    private var selectedProject: FfiProject? {
        projectsVM.projects.first { $0.id == projectsVM.selectedProjectId }
    }

    private func refreshEnvironmentCounts() {
        guard let projId = projectsVM.selectedProjectId, let session = appState.session else { return }
        envsVM.load(projectId: projId, session: session)
    }
}
