import SwiftUI

struct ProjectListView: View {
    @Environment(AppState.self) private var appState
    @Bindable var vm: ProjectsViewModel
    @State private var showingNew = false
    @State private var renamingId: String?
    @State private var renameText = ""
    @State private var pendingDelete: FfiProject?
    @State private var joinRequest: JoinRequest?

    private struct JoinRequest: Identifiable {
        let id = UUID()
        let link: String
    }

    var body: some View {
        List(selection: $vm.selectedProjectId) {
            Section("Projects") {
                ForEach(vm.projects) { proj in
                    row(proj).tag(proj.id)
                }
            }
        }
        .overlay {
            if vm.projects.isEmpty {
                ContentUnavailableView {
                    Label("No projects", systemImage: "folder.badge.plus")
                } description: {
                    Text("A project holds the environments and variables for one app.")
                } actions: {
                    Button("New Project") { showingNew = true }
                        .buttonStyle(.borderedProminent)
                    Button("Join Shared Project…") { joinRequest = JoinRequest(link: "") }
                }
            }
        }
        .safeAreaInset(edge: .bottom, spacing: 0) {
            ColumnFooter {
                Button { showingNew = true } label: {
                    Label("New", systemImage: "plus")
                }
                .buttonStyle(.borderless)
                .help("New project")
                Button { joinRequest = JoinRequest(link: "") } label: {
                    Label("Join", systemImage: "person.badge.plus")
                }
                .buttonStyle(.borderless)
                .help("Join a project someone shared with you")
                Spacer()
                Button { appState.lock() } label: {
                    Image(systemName: "lock")
                }
                .buttonStyle(.borderless)
                .help("Lock vault (⇧⌘L)")
            }
        }
        .sheet(isPresented: $showingNew) {
            NewProjectSheet { name, withDefaults in
                guard let session = appState.session else { return }
                vm.createProject(name: name, withDefaultEnvironments: withDefaults, session: session)
            }
        }
        .sheet(item: $joinRequest) { req in
            if let session = appState.session {
                JoinSheet(session: session, link: req.link) { projectId in
                    vm.load(session: session)
                    vm.selectedProjectId = projectId
                }
            }
        }
        .onAppear(perform: consumePendingLink)
        .onChange(of: appState.pendingJoinLink) { _, _ in consumePendingLink() }
        .confirmationDialog(
            "Delete “\(pendingDelete?.name ?? "")”?",
            isPresented: Binding(get: { pendingDelete != nil }, set: { if !$0 { pendingDelete = nil } }),
            titleVisibility: .visible
        ) {
            Button("Delete Project", role: .destructive) {
                if let p = pendingDelete, let session = appState.session {
                    vm.deleteProject(id: p.id, session: session)
                }
                pendingDelete = nil
            }
        } message: {
            Text(vm.sharedIds.contains(pendingDelete?.id ?? "")
                 ? "This project is shared. Deleting it here stops syncing it and removes it from this Mac. This can't be undone."
                 : "All environments and variables in this project are deleted. This can't be undone.")
        }
        .errorAlert($vm.errorMessage)
    }

    @ViewBuilder
    private func row(_ proj: FfiProject) -> some View {
        if renamingId == proj.id {
            TextField("Project name", text: $renameText)
                .textFieldStyle(.plain)
                .onSubmit(commitRename)
                .onExitCommand { renamingId = nil }
        } else {
            Label(proj.name, systemImage: vm.sharedIds.contains(proj.id) ? "person.2.fill" : "folder")
                .contextMenu {
                    Button("Rename…") {
                        renamingId = proj.id
                        renameText = proj.name
                    }
                    Divider()
                    Button("Delete…", role: .destructive) { pendingDelete = proj }
                }
        }
    }

    private func consumePendingLink() {
        guard let link = appState.pendingJoinLink else { return }
        appState.pendingJoinLink = nil
        joinRequest = JoinRequest(link: link)
    }

    private func commitRename() {
        defer { renamingId = nil }
        let name = renameText.trimmingCharacters(in: .whitespacesAndNewlines)
        guard let id = renamingId, let session = appState.session, !name.isEmpty,
              name != vm.projects.first(where: { $0.id == id })?.name else { return }
        vm.renameProject(id: id, newName: name, session: session)
    }
}

private struct NewProjectSheet: View {
    let onCreate: (String, Bool) -> Void
    @Environment(\.dismiss) private var dismiss
    @State private var name = ""
    @State private var withDefaults = true

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("New Project").font(.title3.bold())
            TextField("Project name", text: $name)
                .textFieldStyle(.roundedBorder)
                .onSubmit(create)
            Toggle("Create development, staging and production environments", isOn: $withDefaults)
            HStack {
                Spacer()
                Button("Cancel", role: .cancel) { dismiss() }
                    .keyboardShortcut(.cancelAction)
                Button("Create", action: create)
                    .keyboardShortcut(.defaultAction)
                    .buttonStyle(.borderedProminent)
                    .disabled(trimmed.isEmpty)
            }
        }
        .padding(20)
        .frame(width: 400)
    }

    private var trimmed: String { name.trimmingCharacters(in: .whitespacesAndNewlines) }

    private func create() {
        guard !trimmed.isEmpty else { return }
        onCreate(trimmed, withDefaults)
        dismiss()
    }
}
