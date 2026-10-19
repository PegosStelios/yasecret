import SwiftUI

extension FfiDiffRow: Identifiable {
    public var id: String { key }
}

struct ComparePair: Identifiable {
    let id = UUID()
    let left: FfiEnvironment
    let right: FfiEnvironment
}

struct CompareSheet: View {
    let pair: ComparePair
    let projectId: String
    let session: YasecretSession
    @Environment(\.dismiss) private var dismiss

    @State private var rows: [FfiDiffRow] = []
    @State private var differencesOnly = true
    @State private var showSecrets = false
    @State private var error: String?

    private var shown: [FfiDiffRow] {
        differencesOnly ? rows.filter { $0.status != "same" } : rows
    }

    var body: some View {
        VStack(alignment: .leading, spacing: Layout.sheetSpacing) {
            HStack {
                Text("\(pair.left.name)  ↔  \(pair.right.name)").font(.title3.bold())
                Spacer()
                Toggle("Differences only", isOn: $differencesOnly)
                Toggle("Show secret values", isOn: $showSecrets)
            }
            HStack(spacing: 16) {
                count("different", "Different", .orange)
                count("only_left", "Only in \(pair.left.name)", .blue)
                count("only_right", "Only in \(pair.right.name)", .purple)
                count("same", "Same", .secondary)
            }
            if shown.isEmpty {
                ContentUnavailableView(rows.isEmpty ? "Both environments are empty" : "No differences",
                                       systemImage: "checkmark.circle")
                    .frame(maxHeight: .infinity)
            } else {
                Table(shown) {
                    TableColumn("Key") { r in
                        Text(r.key).font(.system(.body, design: .monospaced))
                    }
                    .width(min: 140, ideal: 200)
                    TableColumn(pair.left.name) { r in
                        cell(r.leftValue, secret: r.leftIsSecret)
                    }
                    TableColumn(pair.right.name) { r in
                        cell(r.rightValue, secret: r.rightIsSecret)
                    }
                    TableColumn("") { r in
                        Text(statusLabel(r.status))
                            .font(.caption.weight(.medium))
                            .foregroundStyle(statusColor(r.status))
                    }
                    .width(90)
                }
                .alternatingRowBackgrounds(.disabled)
            }
            SheetError(text: error)
            HStack {
                Spacer()
                Button("Done") { dismiss() }.keyboardShortcut(.defaultAction)
            }
        }
        .padding(20)
        .frame(width: Layout.sheetWide, height: sheetHeight)
        .onAppear {
            do {
                rows = try session.compareEnvironments(projectId: projectId, leftEnvId: pair.left.id, rightEnvId: pair.right.id)
            } catch {
                self.error = userMessage(error)
            }
        }
    }

    /// Sized to the rows instead of a fixed height full of empty space.
    private var sheetHeight: CGFloat {
        min(560, 190 + CGFloat(max(shown.count, 4)) * 26)
    }

    private func count(_ status: String, _ label: String, _ color: Color) -> some View {
        Text("\(rows.filter { $0.status == status }.count) \(label.lowercased())")
            .font(.callout)
            .foregroundStyle(color)
    }

    @ViewBuilder
    private func cell(_ value: String?, secret: Bool) -> some View {
        if let value {
            Text(secret && !showSecrets ? Layout.mask : (value.isEmpty ? "empty" : value))
                .italic(value.isEmpty && !(secret && !showSecrets))
                .font(.system(.body, design: .monospaced))
                .lineLimit(1)
                .truncationMode(.middle)
                .foregroundStyle(secret && !showSecrets ? .secondary : .primary)
        } else {
            Text("—").foregroundStyle(.tertiary)
        }
    }

    private func statusLabel(_ s: String) -> String {
        switch s {
        case "same": return "Same"
        case "different": return "Different"
        case "only_left": return "Missing →"
        default: return "← Missing"
        }
    }

    private func statusColor(_ s: String) -> Color {
        switch s {
        case "same": return .secondary
        case "different": return .orange
        case "only_left": return .blue
        default: return .purple
        }
    }
}
