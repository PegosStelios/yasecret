import SwiftUI
import AppKit

struct ExportSheet: View {
    let projectId: String
    let projectName: String
    let envId: String
    let envName: String
    let secrets: [FfiSecret]
    let session: YasecretSession
    var onSaved: (String) -> Void = { _ in }
    @Environment(\.dismiss) private var dismiss

    enum Format: String, CaseIterable, Identifiable {
        case dotenv, json, dockerCompose = "docker-compose", k8sSecret = "k8s-secret", k8sConfigMap = "k8s-configmap", example
        var id: String { rawValue }
        var label: String {
            switch self {
            case .dotenv: return ".env"
            case .json: return "JSON"
            case .dockerCompose: return "Docker Compose"
            case .k8sSecret: return "Kubernetes Secret"
            case .k8sConfigMap: return "Kubernetes ConfigMap"
            case .example: return ".env.example (keys only)"
            }
        }
        var filename: String {
            switch self {
            case .dotenv: return ".env"
            case .json: return "env.json"
            case .dockerCompose: return "docker-compose.env.yml"
            case .k8sSecret: return "secret.yaml"
            case .k8sConfigMap: return "configmap.yaml"
            case .example: return ".env.example"
            }
        }
        var usesName: Bool { self == .dockerCompose || self == .k8sSecret || self == .k8sConfigMap }
    }

    @State private var format: Format = .dotenv
    @State private var includeSecrets = true
    @State private var selected: Set<String> = []
    @State private var resourceName = ""
    @State private var preview = ""
    @State private var error: String?
    @State private var copied = false

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("Export \(envName)").font(.title3.bold())
            HStack(alignment: .top, spacing: 16) {
                VStack(alignment: .leading, spacing: 10) {
                    Picker("Format", selection: $format) {
                        ForEach(Format.allCases) { Text($0.label).tag($0) }
                    }
                    if format.usesName {
                        TextField(format == .dockerCompose ? "Service name" : "Resource name", text: $resourceName)
                            .textFieldStyle(.roundedBorder)
                    }
                    if format != .example {
                        Toggle("Include secret values", isOn: $includeSecrets)
                    }
                    HStack {
                        Text("Variables").font(.headline)
                        Spacer()
                        Button(selected.count == secrets.count ? "None" : "All") {
                            selected = selected.count == secrets.count ? [] : Set(secrets.map(\.key))
                        }
                        .buttonStyle(.link)
                    }
                    List(secrets) { s in
                        Toggle(isOn: Binding(
                            get: { selected.contains(s.key) },
                            set: { on in if on { selected.insert(s.key) } else { selected.remove(s.key) } }
                        )) {
                            HStack(spacing: 4) {
                                Image(systemName: s.isSecret ? "lock.fill" : "textformat").font(.caption2).foregroundStyle(.secondary)
                                Text(s.key).font(.system(.callout, design: .monospaced))
                            }
                        }
                    }
                    .frame(minHeight: 180)
                }
                .frame(width: 260)

                VStack(alignment: .leading, spacing: 6) {
                    Text("Preview").font(.headline)
                    ScrollView {
                        Text(preview.isEmpty ? "Nothing selected" : preview)
                            .font(.system(.caption, design: .monospaced))
                            .foregroundStyle(preview.isEmpty ? .secondary : .primary)
                            .textSelection(.enabled)
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .padding(8)
                    }
                    .background(Color(nsColor: .textBackgroundColor), in: RoundedRectangle(cornerRadius: 6))
                    .overlay(RoundedRectangle(cornerRadius: 6).stroke(.separator))
                    if includeSecrets && format != .example && secrets.contains(where: { $0.isSecret && selected.contains($0.key) }) {
                        Label("Contains secret values in plain text. Don't commit this file.", systemImage: "exclamationmark.triangle")
                            .font(.caption)
                            .foregroundStyle(.orange)
                    }
                }
            }
            if let error {
                Text(error).foregroundStyle(.red).font(.callout)
            }
            HStack {
                Spacer()
                Button("Cancel", role: .cancel) { dismiss() }.keyboardShortcut(.cancelAction)
                Button(copied ? "Copied" : "Copy") {
                    Clipboard.copy(preview, sensitive: includeSecrets && format != .example)
                    copied = true
                    DispatchQueue.main.asyncAfter(deadline: .now() + 1.5) { copied = false }
                }
                .disabled(preview.isEmpty)
                Button("Save…", action: save)
                    .keyboardShortcut(.defaultAction)
                    .buttonStyle(.borderedProminent)
                    .disabled(preview.isEmpty)
            }
        }
        .padding(20)
        .frame(width: 760, height: 520)
        .onAppear {
            selected = Set(secrets.map(\.key))
            resourceName = projectName
            render()
        }
        .onChange(of: format) { _, _ in render() }
        .onChange(of: includeSecrets) { _, _ in render() }
        .onChange(of: selected) { _, _ in render() }
        .onChange(of: resourceName) { _, _ in render() }
    }

    private func render() {
        guard !selected.isEmpty else { preview = ""; return }
        do {
            preview = try session.exportVariables(
                projectId: projectId, envId: envId, format: format.rawValue,
                keys: Array(selected), includeSecretValues: includeSecrets && format != .example,
                name: resourceName.isEmpty ? projectName : resourceName)
            error = nil
        } catch {
            preview = ""
            self.error = userMessage(error)
        }
    }

    private func save() {
        let panel = NSSavePanel()
        panel.nameFieldStringValue = format.filename
        panel.showsHiddenFiles = true
        guard panel.runModal() == .OK, let url = panel.url else { return }
        do {
            try preview.write(to: url, atomically: true, encoding: .utf8)
            onSaved(url.lastPathComponent)
            dismiss()
        } catch {
            self.error = error.localizedDescription
        }
    }
}
