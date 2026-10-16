import SwiftUI

struct MainView: View {
    @Environment(AppState.self) private var appState
    @State private var projectsVM = ProjectsViewModel()
    @State private var envsVM = EnvironmentsViewModel()
    @State private var secretsVM = SecretsViewModel()
    @State private var sharingVM = SharingViewModel()
    @State private var showingShare = false

    var body: some View {
        NavigationSplitView {
            ProjectListView(vm: projectsVM)
                .navigationSplitViewColumnWidth(min: 180, ideal: 210, max: 280)
        } content: {
            Group {
                if let proj = selectedProject {
                    EnvironmentListView(vm: envsVM, projectId: proj.id, projectName: proj.name,
                                        sharing: sharingVM, onShare: { showingShare = true })
                } else {
                    ContentUnavailableView("Select a project", systemImage: "folder",
                                           description: Text("Pick a project on the left, or create one."))
                }
            }
            .navigationSplitViewColumnWidth(min: 180, ideal: 210, max: 280)
        } detail: {
            if let env = envsVM.selectedEnvironment, let proj = selectedProject {
                SecretListView(vm: secretsVM, projectId: proj.id, envId: env.id, envName: env.name,
                               projectName: proj.name, readOnly: sharingVM.isReadOnly, onChanged: refreshEnvironmentCounts)
                    .id(env.id)
            } else {
                ContentUnavailableView("Select an environment", systemImage: "list.bullet.rectangle")
            }
        }
        .frame(minWidth: 1040, minHeight: 560)
        .sheet(isPresented: $showingShare) {
            if let proj = selectedProject, let session = appState.session {
                ShareSheet(projectId: proj.id, projectName: proj.name, session: session, sharing: sharingVM) {
                    projectsVM.load(session: session)
                    if let pid = projectsVM.selectedProjectId { envsVM.load(projectId: pid, session: session) }
                }
            }
        }
        .task(id: projectsVM.selectedProjectId) {
            while !Task.isCancelled {
                if let pid = projectsVM.selectedProjectId, let session = appState.session {
                    sharingVM.refresh(projectId: pid, session: session)
                } else {
                    sharingVM.clear()
                }
                try? await Task.sleep(for: .seconds(5))
            }
        }
        .onChange(of: appState.dataRevision) { _, _ in reloadAfterSync() }
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

    /// Another device changed something: reload every column without losing selection.
    private func reloadAfterSync() {
        guard let session = appState.session else { return }
        projectsVM.load(session: session)
        guard let pid = projectsVM.selectedProjectId else { return }
        envsVM.load(projectId: pid, session: session)
        sharingVM.refresh(projectId: pid, session: session)
        if let eid = envsVM.selectedEnvId { secretsVM.load(envId: eid, session: session) }
    }

    private func refreshEnvironmentCounts() {
        guard let projId = projectsVM.selectedProjectId, let session = appState.session else { return }
        envsVM.load(projectId: projId, session: session)
    }
}
