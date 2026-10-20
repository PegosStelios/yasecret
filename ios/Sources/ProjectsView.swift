import SwiftUI

struct ProjectsView: View {
    let session: YasecretSession
    @Environment(MobileState.self) private var state
    @State private var projects: [FfiProject] = []
    @State private var showingJoin = false

    var body: some View {
        NavigationStack {
            List(projects, id: \.id) { p in
                NavigationLink(value: p.id) { Label(p.name, systemImage: "folder") }
            }
            .overlay {
                if projects.isEmpty {
                    ContentUnavailableView {
                        Label("No projects yet", systemImage: "folder")
                    } description: {
                        Text("Ask a teammate to share a project with this phone, then join it here.")
                    } actions: {
                        Button("Join a Project") { showingJoin = true }.buttonStyle(.borderedProminent)
                    }
                }
            }
            .navigationTitle("Projects")
            .navigationDestination(for: String.self) { pid in
                EnvironmentsView(session: session, project: projects.first { $0.id == pid })
            }
            .toolbar {
                ToolbarItem(placement: .topBarLeading) {
                    Button { state.lock() } label: { Image(systemName: "lock") }
                        .accessibilityLabel("Lock")
                }
                ToolbarItem(placement: .topBarTrailing) {
                    Button { showingJoin = true } label: { Image(systemName: "person.badge.plus") }
                        .accessibilityLabel("Join a project")
                }
            }
            .sheet(isPresented: $showingJoin, onDismiss: load) { JoinView(session: session) }
            .refreshable { load() }
        }
        .onAppear(perform: load)
        .onChange(of: state.revision) { _, _ in load() }
        .onChange(of: state.pendingJoinLink) { _, link in if link != nil { showingJoin = true } }
    }

    private func load() {
        projects = (try? session.listProjects()) ?? []
    }
}

struct EnvironmentsView: View {
    let session: YasecretSession
    let project: FfiProject?
    @Environment(MobileState.self) private var state
    @State private var envs: [FfiEnvironment] = []

    var body: some View {
        List(envs, id: \.id) { e in
            NavigationLink {
                VariablesView(session: session, projectId: project?.id ?? "", env: e)
            } label: {
                VStack(alignment: .leading) {
                    Text(e.name)
                    if let parent = envs.first(where: { $0.id == e.inheritsFrom }) {
                        Text("inherits \(parent.name)").font(.caption).foregroundStyle(.secondary)
                    }
                }
                .badge(Int(e.secretCount))
            }
        }
        .navigationTitle(project?.name ?? "")
        .onAppear(perform: load)
        .onChange(of: state.revision) { _, _ in load() }
        .refreshable { load() }
    }

    private func load() {
        guard let pid = project?.id else { return }
        envs = (try? session.listEnvironments(projectId: pid)) ?? []
    }
}
