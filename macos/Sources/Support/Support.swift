import SwiftUI
import AppKit

extension FfiSecret: Identifiable {}
extension FfiEnvironment: Identifiable {}
extension FfiProject: Identifiable {}

func userMessage(_ error: Error) -> String {
    guard let e = error as? FfiError else { return error.localizedDescription }
    switch e {
    case .WrongPassword: return "Wrong password"
    case .NotFound(let msg): return "Not found: \(msg)"
    case .PermissionDenied: return "You don't have permission to do that"
    case .Crypto: return "Couldn't decrypt this value with the vault key"
    case .Io(let msg): return "File error: \(msg)"
    case .Db(let msg): return "Database error: \(msg)"
    case .Parse(let msg): return msg
    case .Sync(let msg): return msg
    }
}

enum Clipboard {
    /// Copies text; sensitive values are cleared after `clearAfter` seconds unless something else was copied since.
    static func copy(_ text: String, sensitive: Bool, clearAfter: TimeInterval = 60) {
        let pb = NSPasteboard.general
        pb.clearContents()
        pb.setString(text, forType: .string)
        guard sensitive else { return }
        let stamp = pb.changeCount
        DispatchQueue.main.asyncAfter(deadline: .now() + clearAfter) {
            if NSPasteboard.general.changeCount == stamp {
                NSPasteboard.general.clearContents()
            }
        }
    }
}

struct ErrorAlert: ViewModifier {
    @Binding var message: String?

    func body(content: Content) -> some View {
        content.alert(
            "Something went wrong",
            isPresented: Binding(get: { message != nil }, set: { if !$0 { message = nil } })
        ) {
            Button("OK", role: .cancel) { message = nil }
        } message: {
            Text(message ?? "")
        }
    }
}

extension View {
    func errorAlert(_ message: Binding<String?>) -> some View {
        modifier(ErrorAlert(message: message))
    }
}

/// Footer bar pinned to the bottom of a sidebar column.
struct ColumnFooter<Content: View>: View {
    @ViewBuilder var content: Content

    var body: some View {
        VStack(spacing: 0) {
            Divider()
            HStack(spacing: 8) { content }
                .padding(.horizontal, 10)
                .padding(.vertical, 7)
        }
        .background(.regularMaterial)
    }
}

struct NameSheet: View {
    let title: String
    let placeholder: String
    let actionLabel: String
    @State var name: String
    var footnote: String?
    let onSubmit: (String) -> Void
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text(title).font(.title3.bold())
            TextField(placeholder, text: $name)
                .textFieldStyle(.roundedBorder)
                .onSubmit(submit)
            if let footnote {
                Text(footnote).font(.caption).foregroundStyle(.secondary)
            }
            HStack {
                Spacer()
                Button("Cancel", role: .cancel) { dismiss() }
                    .keyboardShortcut(.cancelAction)
                Button(actionLabel, action: submit)
                    .keyboardShortcut(.defaultAction)
                    .buttonStyle(.borderedProminent)
                    .disabled(trimmed.isEmpty)
            }
        }
        .padding(20)
        .frame(width: 360)
    }

    private var trimmed: String { name.trimmingCharacters(in: .whitespacesAndNewlines) }

    private func submit() {
        guard !trimmed.isEmpty else { return }
        onSubmit(trimmed)
        dismiss()
    }
}
