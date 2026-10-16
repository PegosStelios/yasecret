import SwiftUI
import AppKit

struct SecretListView: View {
    @Environment(AppState.self) private var appState
    @Bindable var vm: SecretsViewModel
    let projectId: String
    let envId: String
    let envName: String
    var readOnly = false
    var onChanged: () -> Void = {}

    @State private var selection = Set<String>()
    @State private var revealed: [String: String] = [:]
    @State private var plainValues: [String: String] = [:]
    @State private var editor: EditorRequest?
    @State private var showingImport = false
    @State private var pendingDelete: [FfiSecret] = []
    @State private var copiedId: String?
    @State private var banner: String?

    var body: some View {
        VStack(spacing: 0) {
            header
            if let banner {
                Text(banner)
                    .font(.callout)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(.horizontal, 16)
                    .padding(.vertical, 6)
                    .background(Color.green.opacity(0.12))
                    .transition(.move(edge: .top).combined(with: .opacity))
            }
            Divider()
            content
        }
        .sheet(item: $editor) { req in
            if let session = appState.session {
                SecretEditorView(request: req, projectId: projectId, envId: envId,
                                 vm: vm, session: session, onSaved: onChanged)
            }
        }
        .sheet(isPresented: $showingImport) {
            if let session = appState.session {
                ImportEnvView(projectId: projectId, envId: envId, envName: envName,
                              session: session) { summary in
                    vm.load(envId: envId, session: session)
                    onChanged()
                    showBanner("Imported: \(summary.added) added, \(summary.updated) updated, \(summary.skipped) skipped")
                }
            }
        }
        .confirmationDialog(
            pendingDelete.count == 1
                ? "Delete \(pendingDelete[0].key)?"
                : "Delete \(pendingDelete.count) variables?",
            isPresented: Binding(get: { !pendingDelete.isEmpty }, set: { if !$0 { pendingDelete = [] } }),
            titleVisibility: .visible
        ) {
            Button("Delete", role: .destructive, action: deletePending)
        } message: {
            Text("Removed from \(envName). This can't be undone.")
        }
        .errorAlert($vm.errorMessage)
        .task(id: vm.secrets) { loadPlainValues() }
    }

    // MARK: Header

    private var header: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack(alignment: .firstTextBaseline, spacing: 10) {
                VStack(alignment: .leading, spacing: 2) {
                    Text(envName).font(.title2.weight(.semibold))
                    Text(countLabel).font(.callout).foregroundStyle(.secondary)
                }
                Spacer()
                if readOnly {
                    Label("View only", systemImage: "eye")
                        .foregroundStyle(.secondary)
                        .help("The project owner gave you view access")
                } else {
                    Button { showingImport = true } label: {
                        Label("Import", systemImage: "square.and.arrow.down")
                    }
                    .help("Import a .env or JSON file")
                }
                Button(action: export) {
                    Label("Export", systemImage: "square.and.arrow.up")
                }
                .disabled(vm.secrets.isEmpty)
                .help("Save this environment as a .env file")
                if !readOnly {
                    Button { editor = EditorRequest(secret: nil) } label: {
                        Label("Add Variable", systemImage: "plus")
                    }
                    .buttonStyle(.borderedProminent)
                    .keyboardShortcut("n", modifiers: [.command])
                }
            }
            HStack(spacing: 6) {
                Image(systemName: "magnifyingglass").foregroundStyle(.secondary)
                TextField("Search variables", text: $vm.searchText)
                    .textFieldStyle(.plain)
                if !vm.searchText.isEmpty {
                    Button { vm.searchText = "" } label: {
                        Image(systemName: "xmark.circle.fill").foregroundStyle(.secondary)
                    }
                    .buttonStyle(.borderless)
                }
            }
            .padding(.horizontal, 8)
            .padding(.vertical, 6)
            .background(.quaternary.opacity(0.6), in: RoundedRectangle(cornerRadius: 7))
        }
        .padding(.horizontal, 16)
        .padding(.top, 14)
        .padding(.bottom, 10)
    }

    private var countLabel: String {
        let secrets = vm.secrets.filter(\.isSecret).count
        let plain = vm.secrets.count - secrets
        return "\(vm.secrets.count) variable\(vm.secrets.count == 1 ? "" : "s") · \(secrets) secret · \(plain) plain"
    }

    // MARK: Content

    @ViewBuilder
    private var content: some View {
        if vm.secrets.isEmpty {
            ContentUnavailableView {
                Label("No variables in \(envName)", systemImage: "key")
            } description: {
                Text("Add variables one by one, or import an existing .env or JSON file.")
            } actions: {
                if !readOnly {
                    Button("Add Variable") { editor = EditorRequest(secret: nil) }
                        .buttonStyle(.borderedProminent)
                    Button("Import…") { showingImport = true }
                }
            }
        } else if vm.filtered.isEmpty {
            ContentUnavailableView.search(text: vm.searchText)
        } else {
            table
        }
    }

    private var table: some View {
        Table(vm.filtered, selection: $selection) {
            TableColumn("Key") { s in
                HStack(spacing: 6) {
                    Image(systemName: s.isSecret ? "lock.fill" : "textformat")
                        .font(.caption)
                        .foregroundStyle(s.isSecret ? Color.orange : Color.secondary)
                        .frame(width: 14)
                        .help(s.isSecret ? "Secret" : "Plain variable")
                    Text(s.key)
                        .font(.system(.body, design: .monospaced))
                }
            }
            .width(min: 140, ideal: 220)

            TableColumn("Value") { s in valueCell(s) }
                .width(min: 180, ideal: 320)

            TableColumn("Updated") { s in
                Text(Date(timeIntervalSince1970: TimeInterval(s.updatedAt)),
                     format: .relative(presentation: .named))
                    .foregroundStyle(.secondary)
            }
            .width(min: 80, ideal: 110)
        }
        .contextMenu(forSelectionType: String.self) { ids in
            menu(for: ids)
        } primaryAction: { ids in
            if !readOnly, let id = ids.first, let s = secret(id) { editor = EditorRequest(secret: s) }
        }
        .onDeleteCommand {
            if !readOnly { pendingDelete = vm.secrets.filter { selection.contains($0.id) } }
        }
    }

    private func valueCell(_ s: FfiSecret) -> some View {
        HStack(spacing: 6) {
            Group {
                if let v = s.isSecret ? revealed[s.id] : plainValues[s.id] {
                    if v.isEmpty {
                        Text("empty").italic().foregroundStyle(.tertiary)
                    } else {
                        Text(v)
                    }
                } else {
                    Text("••••••••••••").foregroundStyle(.secondary)
                }
            }
            .font(.system(.body, design: .monospaced))
            .lineLimit(1)
            .truncationMode(.tail)

            Spacer(minLength: 4)

            if s.isSecret {
                Button { toggleReveal(s) } label: {
                    Image(systemName: revealed[s.id] == nil ? "eye" : "eye.slash")
                }
                .buttonStyle(.borderless)
                .help(revealed[s.id] == nil ? "Reveal value" : "Hide value")
            }
            Button { copyValue(s) } label: {
                Image(systemName: copiedId == s.id ? "checkmark" : "doc.on.doc")
            }
            .buttonStyle(.borderless)
            .help(s.isSecret ? "Copy value (clipboard clears in 60s)" : "Copy value")
        }
    }

    @ViewBuilder
    private func menu(for ids: Set<String>) -> some View {
        if ids.count == 1, let id = ids.first, let s = secret(id) {
            if !readOnly { Button("Edit…") { editor = EditorRequest(secret: s) } }
            Button("Copy Value") { copyValue(s) }
            Button("Copy Key") { Clipboard.copy(s.key, sensitive: false) }
            if s.isSecret {
                Button(revealed[s.id] == nil ? "Reveal Value" : "Hide Value") { toggleReveal(s) }
            }
            if !readOnly {
                Button(s.isSecret ? "Mark as Plain" : "Mark as Secret") { toggleKind(s) }
                Divider()
            }
        }
        if !ids.isEmpty && !readOnly {
            Button(ids.count > 1 ? "Delete \(ids.count) Variables…" : "Delete…", role: .destructive) {
                pendingDelete = vm.secrets.filter { ids.contains($0.id) }
            }
        }
    }

    // MARK: Actions

    private func secret(_ id: String) -> FfiSecret? {
        vm.secrets.first { $0.id == id }
    }

    private func plaintext(_ s: FfiSecret) -> String? {
        guard let session = appState.session else { return nil }
        do {
            return try session.getSecretPlaintext(projectId: projectId, secretId: s.id)
        } catch {
            vm.errorMessage = userMessage(error)
            return nil
        }
    }

    private func loadPlainValues() {
        var values: [String: String] = [:]
        for s in vm.secrets where !s.isSecret {
            values[s.id] = plaintext(s)
        }
        plainValues = values
        revealed = revealed.filter { id, _ in vm.secrets.contains { $0.id == id && $0.isSecret } }
    }

    private func toggleReveal(_ s: FfiSecret) {
        if revealed[s.id] != nil {
            revealed[s.id] = nil
        } else if let v = plaintext(s) {
            revealed[s.id] = v
        }
    }

    private func copyValue(_ s: FfiSecret) {
        guard let v = revealed[s.id] ?? plainValues[s.id] ?? plaintext(s) else { return }
        Clipboard.copy(v, sensitive: s.isSecret)
        copiedId = s.id
        DispatchQueue.main.asyncAfter(deadline: .now() + 1.5) {
            if copiedId == s.id { copiedId = nil }
        }
    }

    private func toggleKind(_ s: FfiSecret) {
        guard let session = appState.session else { return }
        vm.editSecret(projectId: projectId, secret: s, newKey: nil, newValue: nil,
                      isSecret: !s.isSecret, session: session)
    }

    private func deletePending() {
        guard let session = appState.session else { return }
        for s in pendingDelete {
            vm.deleteSecret(id: s.id, session: session)
        }
        selection.subtract(pendingDelete.map(\.id))
        pendingDelete = []
        onChanged()
    }

    private func export() {
        guard let session = appState.session else { return }
        do {
            let exported = try session.exportEnv(projectId: projectId, envId: envId)
            let panel = NSSavePanel()
            panel.nameFieldStringValue = ".env.\(envName)"
            panel.showsHiddenFiles = true
            if panel.runModal() == .OK, let url = panel.url {
                try exported.write(to: url, atomically: true, encoding: .utf8)
                showBanner("Exported \(vm.secrets.count) variables to \(url.lastPathComponent)")
            }
        } catch {
            vm.errorMessage = userMessage(error)
        }
    }

    private func showBanner(_ text: String) {
        withAnimation { banner = text }
        DispatchQueue.main.asyncAfter(deadline: .now() + 4) {
            withAnimation { if banner == text { banner = nil } }
        }
    }
}
