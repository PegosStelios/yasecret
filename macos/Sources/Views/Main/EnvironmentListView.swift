import SwiftUI

struct EnvironmentListView: View {
    @Environment(AppState.self) private var appState
    @Bindable var vm: EnvironmentsViewModel
    let projectId: String
    let projectName: String
    let sharing: SharingViewModel
    var onShare: () -> Void = {}

    private var readOnly: Bool { sharing.isReadOnly }
    @State private var showingNew = false
    @State private var cloning: FfiEnvironment?
    @State private var renamingId: String?
    @State private var renameText = ""
    @State private var pendingDelete: FfiEnvironment?
    @State private var comparing: ComparePair?
    @State private var showingActivity = false

    var body: some View {
        VStack(spacing: 0) {
            VStack(alignment: .leading, spacing: 10) {
                ColumnHeader(title: projectName, subtitle: plural(vm.environments.count, "environment"))
                statusRow
                    .padding(.horizontal, Layout.gutter)
            }
            .padding(.bottom, 10)
            Divider()
            list
        }
        .frame(maxHeight: .infinity, alignment: .top)
        .ignoresSafeArea(.container, edges: .top)
    }

    /// Same height as the variables search field, so both column headers end on one line.
    /// Why sharing can't work right now, if anything is wrong.
    private var problem: String? {
        if let e = sharing.error { return e }
        if sharing.isShared, let e = appState.syncError { return "Sharing unavailable: \(e)" }
        return sharing.status?.lastError
    }

    private var statusColor: Color {
        if problem != nil { return .red }
        guard sharing.isShared else { return Color.secondary.opacity(0.5) }
        return (sharing.status?.peersOnline ?? 0) > 0 ? .green : .orange
    }

    private var statusRow: some View {
        HStack(spacing: 6) {
            Circle()
                .fill(statusColor)
                .frame(width: 7, height: 7)
            Text(problem.map { _ in "Sharing problem — hover for details" } ?? sharing.summary ?? "Not shared")
                .font(.callout)
                .foregroundStyle(.secondary)
                .lineLimit(1)
                .truncationMode(.tail)
            Spacer(minLength: 0)
        }
        .frame(height: 28)
        .padding(.horizontal, 8)
        .background(.quaternary.opacity(0.6), in: RoundedRectangle(cornerRadius: 7))
        .help(problem ?? (sharing.isShared
            ? "Devices sync directly whenever both are open and unlocked"
            : "Use Share to sync this project with teammates"))
    }

    private var list: some View {
        List(selection: $vm.selectedEnvId) {
            ForEach(vm.environments) { env in
                row(env).tag(env.id)
            }
        }
        .overlay {
            if vm.environments.isEmpty {
                ContentUnavailableView {
                    Label("No environments", systemImage: "square.stack.3d.up")
                } description: {
                    Text("Environments keep separate values for development, staging and production.")
                } actions: {
                    if !readOnly {
                        Button("Add Defaults") { addDefaults() }
                            .buttonStyle(.borderedProminent)
                        Button("New Environment") { showingNew = true }
                    }
                }
            }
        }
        .safeAreaInset(edge: .bottom, spacing: 0) {
            ColumnFooter {
                    if !readOnly {
                        Button { showingNew = true } label: {
                            Label("New", systemImage: "plus").fixedSize()
                        }
                        .buttonStyle(.borderless)
                        .help("New environment")
                    }
                    Spacer()
                    Button { showingActivity = true } label: {
                        Image(systemName: "clock.arrow.circlepath")
                    }
                    .buttonStyle(.borderless)
                    .help("Activity")
                    Button(action: onShare) {
                        Label("Share", systemImage: "person.crop.circle.badge.plus")
                            .lineLimit(1)
                            .fixedSize()
                    }
                    .buttonStyle(.borderless)
                    .help("Share this project with teammates")
            }
        }
        .sheet(isPresented: $showingNew) {
            NameSheet(title: "New Environment", placeholder: "e.g. qa, preview, feature-x",
                      actionLabel: "Create", name: "") { name in
                guard let session = appState.session else { return }
                vm.createEnvironment(projectId: projectId, name: name, session: session)
            }
        }
        .sheet(item: $cloning) { env in
            NameSheet(title: "Clone “\(env.name)”", placeholder: "New environment name",
                      actionLabel: "Clone", name: "\(env.name)-copy",
                      footnote: "Copies all \(env.secretCount) variables, values included.") { name in
                guard let session = appState.session else { return }
                vm.cloneEnvironment(id: env.id, newName: name, session: session)
            }
        }
        .sheet(item: $comparing) { pair in
            if let session = appState.session {
                CompareSheet(pair: pair, projectId: projectId, session: session)
            }
        }
        .sheet(isPresented: $showingActivity) {
            if let session = appState.session {
                ActivitySheet(projectId: projectId, projectName: projectName, session: session)
            }
        }
        .confirmationDialog(
            "Delete “\(pendingDelete?.name ?? "")”?",
            isPresented: Binding(get: { pendingDelete != nil }, set: { if !$0 { pendingDelete = nil } }),
            titleVisibility: .visible
        ) {
            Button("Delete Environment", role: .destructive) {
                if let e = pendingDelete, let session = appState.session {
                    vm.deleteEnvironment(id: e.id, session: session)
                }
                pendingDelete = nil
            }
        } message: {
            Text("Its \(pendingDelete?.secretCount ?? 0) variables are deleted too. This can't be undone.")
        }
        .errorAlert($vm.errorMessage)
        .task {
            guard let hook = DevHook.open else { return }
            try? await Task.sleep(for: .milliseconds(600))
            switch hook {
            case "newEnv": showingNew = true
            case "clone": cloning = vm.environments.first
            case "activity": showingActivity = true
            case "compare":
                if vm.environments.count > 1 {
                    comparing = ComparePair(left: vm.environments[0], right: vm.environments[vm.environments.count - 1])
                }
            default: break
            }
        }
    }

    @ViewBuilder
    private func row(_ env: FfiEnvironment) -> some View {
        if renamingId == env.id {
            InlineRenameField(placeholder: "Environment name", text: $renameText,
                              onCommit: commitRename, onCancel: { renamingId = nil })
        } else {
            HStack {
                Label(env.name, systemImage: icon(for: env.name))
                Spacer()
                Text("\(env.secretCount)")
                    .font(.caption.monospacedDigit())
                    .foregroundStyle(.secondary)
            }
            .contextMenu {
                let others = vm.environments.filter { $0.id != env.id }
                if !others.isEmpty {
                    Menu("Compare With") {
                        ForEach(others) { other in
                            Button(other.name) { comparing = ComparePair(left: env, right: other) }
                        }
                    }
                }
                if !readOnly {
                    Button("Rename…") {
                        renamingId = env.id
                        renameText = env.name
                    }
                    Button("Clone…") { cloning = env }
                    Divider()
                    Button("Delete…", role: .destructive) { pendingDelete = env }
                }
            }
        }
    }

    private func icon(for name: String) -> String {
        switch name.lowercased() {
        case let n where n.hasPrefix("prod"): return "bolt.shield"
        case let n where n.hasPrefix("stag"): return "testtube.2"
        case let n where n.hasPrefix("dev") || n.hasPrefix("local"): return "hammer"
        default: return "square.stack.3d.up"
        }
    }

    private func addDefaults() {
        guard let session = appState.session else { return }
        for name in ProjectsViewModel.defaultEnvironments {
            vm.createEnvironment(projectId: projectId, name: name, session: session)
        }
        vm.selectedEnvId = vm.environments.first?.id
    }

    private func commitRename() {
        defer { renamingId = nil }
        let name = renameText.trimmingCharacters(in: .whitespacesAndNewlines)
        guard let id = renamingId, let session = appState.session, !name.isEmpty,
              name != vm.environments.first(where: { $0.id == id })?.name else { return }
        vm.renameEnvironment(id: id, newName: name, session: session)
    }
}
