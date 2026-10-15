import SwiftUI
import AppKit
import UniformTypeIdentifiers

struct ImportEnvView: View {
    let projectId: String
    let envId: String
    let envName: String
    let session: YasecretSession
    let onComplete: (FfiImportSummary) -> Void
    @Environment(\.dismiss) private var dismiss

    struct Draft: Identifiable {
        let id: Int
        let key: String
        let value: String
        let exists: Bool
        var include: Bool
        var isSecret: Bool
    }

    @State private var content = ""
    @State private var drafts: [Draft] = []
    @State private var previewing = false
    @State private var overwrite = false
    @State private var dropTargeted = false
    @State private var error: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("Import into \(envName)").font(.title3.bold())
            if previewing { previewStep } else { sourceStep }
            if let error {
                Text(error).font(.callout).foregroundStyle(.red)
            }
        }
        .padding(20)
        .frame(width: 640, height: 480)
    }

    // MARK: Step 1 — source

    private var sourceStep: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Paste a .env or JSON file, drop one here, or choose a file. Nothing is saved until you confirm the preview.")
                .font(.callout)
                .foregroundStyle(.secondary)

            ZStack {
                TextEditor(text: $content)
                    .font(.system(.body, design: .monospaced))
                    .scrollContentBackground(.hidden)
                    .padding(6)
                if content.isEmpty {
                    VStack(spacing: 6) {
                        Image(systemName: "doc.badge.arrow.up").font(.largeTitle)
                        Text("DATABASE_URL=postgres://…\nAPI_KEY=sk_live_…")
                            .font(.system(.callout, design: .monospaced))
                            .multilineTextAlignment(.center)
                    }
                    .foregroundStyle(.tertiary)
                    .allowsHitTesting(false)
                }
            }
            .background(Color(nsColor: .textBackgroundColor), in: RoundedRectangle(cornerRadius: 8))
            .overlay(
                RoundedRectangle(cornerRadius: 8)
                    .stroke(dropTargeted ? Color.accentColor : Color.secondary.opacity(0.3),
                            style: StrokeStyle(lineWidth: dropTargeted ? 2 : 1, dash: dropTargeted ? [] : [5]))
            )
            .onDrop(of: [.fileURL], isTargeted: $dropTargeted, perform: handleDrop)

            HStack {
                Button("Choose File…", action: chooseFile)
                Spacer()
                Button("Cancel", role: .cancel) { dismiss() }
                    .keyboardShortcut(.cancelAction)
                Button("Preview", action: buildPreview)
                    .keyboardShortcut(.defaultAction)
                    .buttonStyle(.borderedProminent)
                    .disabled(content.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
            }
        }
    }

    // MARK: Step 2 — preview

    private var previewStep: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack(spacing: 14) {
                summaryChip("\(drafts.filter { !$0.exists }.count) new", .green)
                summaryChip("\(drafts.filter(\.exists).count) already exist", .orange)
                summaryChip("\(drafts.filter(\.isSecret).count) secret", .secondary)
                Spacer()
                if drafts.contains(where: \.exists) {
                    Picker("Existing:", selection: $overwrite) {
                        Text("Skip").tag(false)
                        Text("Overwrite").tag(true)
                    }
                    .pickerStyle(.segmented)
                    .frame(width: 220)
                }
            }

            Table(drafts) {
                TableColumn("") { d in
                    Toggle("", isOn: binding(d.id, \.include)).labelsHidden()
                }
                .width(24)
                TableColumn("Key") { d in
                    Text(d.key).font(.system(.body, design: .monospaced))
                }
                .width(min: 140, ideal: 200)
                TableColumn("Value") { d in
                    Text(d.isSecret ? String(repeating: "•", count: min(max(d.value.count, 4), 12)) : d.value)
                        .font(.system(.body, design: .monospaced))
                        .foregroundStyle(d.isSecret ? .secondary : .primary)
                        .lineLimit(1)
                }
                .width(min: 120, ideal: 200)
                TableColumn("Status") { d in
                    Text(d.exists ? (overwrite ? "Overwrite" : "Skip") : "New")
                        .font(.caption.weight(.medium))
                        .foregroundStyle(d.exists ? Color.orange : Color.green)
                }
                .width(70)
                TableColumn("Secret") { d in
                    Toggle("", isOn: binding(d.id, \.isSecret)).labelsHidden()
                }
                .width(50)
            }

            Text("Names containing KEY, TOKEN, SECRET, PASSWORD, PRIVATE, AUTH or CREDENTIAL are marked secret automatically.")
                .font(.caption)
                .foregroundStyle(.secondary)

            HStack {
                Button("Back") { previewing = false; error = nil }
                Spacer()
                Button("Cancel", role: .cancel) { dismiss() }
                    .keyboardShortcut(.cancelAction)
                Button(importLabel, action: apply)
                    .keyboardShortcut(.defaultAction)
                    .buttonStyle(.borderedProminent)
                    .disabled(effectiveCount == 0)
            }
        }
    }

    private func summaryChip(_ text: String, _ color: Color) -> some View {
        Text(text)
            .font(.callout.weight(.medium))
            .foregroundStyle(color)
    }

    private var effectiveCount: Int {
        drafts.filter { $0.include && (!$0.exists || overwrite) }.count
    }

    private var importLabel: String {
        "Import \(effectiveCount) Variable\(effectiveCount == 1 ? "" : "s")"
    }

    private func binding(_ id: Int, _ kp: WritableKeyPath<Draft, Bool>) -> Binding<Bool> {
        Binding(get: { drafts[id][keyPath: kp] }, set: { drafts[id][keyPath: kp] = $0 })
    }

    // MARK: Actions

    private func chooseFile() {
        let panel = NSOpenPanel()
        panel.canChooseFiles = true
        panel.canChooseDirectories = false
        panel.showsHiddenFiles = true
        if panel.runModal() == .OK, let url = panel.url {
            load(url)
        }
    }

    private func handleDrop(_ providers: [NSItemProvider]) -> Bool {
        guard let provider = providers.first else { return false }
        _ = provider.loadObject(ofClass: URL.self) { url, _ in
            guard let url else { return }
            Task { @MainActor in load(url) }
        }
        return true
    }

    private func load(_ url: URL) {
        do {
            content = try String(contentsOf: url, encoding: .utf8)
            error = nil
        } catch {
            self.error = "Couldn't read \(url.lastPathComponent): \(error.localizedDescription)"
        }
    }

    private func buildPreview() {
        do {
            let rows = try session.previewImport(envId: envId, content: content)
            // Later lines win when a file repeats a key, matching how dotenv loaders behave.
            var lastIndex: [String: Int] = [:]
            for (i, r) in rows.enumerated() { lastIndex[r.key] = i }
            let unique = rows.enumerated().filter { lastIndex[$0.element.key] == $0.offset }.map(\.element)
            drafts = unique.enumerated().map { i, r in
                Draft(id: i, key: r.key, value: r.value, exists: r.exists,
                      include: isValidKey(key: r.key), isSecret: r.suggestedSecret)
            }
            if drafts.isEmpty {
                error = "No variables found."
                return
            }
            let invalid = drafts.filter { !isValidKey(key: $0.key) }.map(\.key)
            error = invalid.isEmpty ? nil : "Unchecked invalid names: \(invalid.joined(separator: ", "))"
            previewing = true
        } catch {
            self.error = userMessage(error)
        }
    }

    private func apply() {
        let items = drafts
            .filter { $0.include && (!$0.exists || overwrite) }
            .map { FfiImportItem(key: $0.key, value: $0.value, isSecret: $0.isSecret) }
        do {
            let summary = try session.applyImport(projectId: projectId, envId: envId,
                                                  items: items, overwrite: overwrite)
            let skipped = drafts.count - items.count
            onComplete(FfiImportSummary(added: summary.added, updated: summary.updated,
                                        skipped: summary.skipped + UInt32(skipped)))
            dismiss()
        } catch {
            self.error = userMessage(error)
        }
    }
}
