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

enum Layout {
    static let gutter: CGFloat = 16
    /// Column headers sit in the window's top band, level with the traffic lights.
    static let headerTop: CGFloat = 14
    static let footerHeight: CGFloat = 36
}

/// Title block shared by the environment and variable columns so they line up.
struct ColumnHeader<Trailing: View>: View {
    let title: String
    let subtitle: String
    @ViewBuilder var trailing: Trailing

    var body: some View {
        HStack(alignment: .center, spacing: 10) {
            VStack(alignment: .leading, spacing: 2) {
                Text(title).font(.title2.weight(.semibold)).lineLimit(1)
                Text(subtitle).font(.callout).foregroundStyle(.secondary).lineLimit(1)
            }
            Spacer(minLength: 8)
            trailing
        }
        .padding(.horizontal, Layout.gutter)
        .padding(.top, Layout.headerTop)
        .frame(minHeight: 44 + Layout.headerTop, alignment: .bottom)
    }
}

extension ColumnHeader where Trailing == EmptyView {
    init(title: String, subtitle: String) {
        self.init(title: title, subtitle: subtitle) { EmptyView() }
    }
}

/// Footer bar pinned to the bottom of a column; every column uses the same height.
struct ColumnFooter<Content: View>: View {
    @ViewBuilder var content: Content

    var body: some View {
        VStack(spacing: 0) {
            Divider()
            HStack(spacing: 12) { content }
                .labelStyle(.titleAndIcon)
                .padding(.horizontal, 12)
                .frame(height: Layout.footerHeight)
        }
        .background(.regularMaterial)
    }
}

func plural(_ n: Int, _ word: String) -> String {
    "\(n) \(word)\(n == 1 ? "" : "s")"
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

/// Debug-only launch hooks for UI testing and screenshots (absent from release builds).
enum DevHook {
    static var open: String? {
        #if DEBUG
        ProcessInfo.processInfo.environment["YASECRET_DEV_OPEN"]
        #else
        nil
        #endif
    }

    static var importText: String {
        #if DEBUG
        ProcessInfo.processInfo.environment["YASECRET_DEV_IMPORT"]?.replacingOccurrences(of: "\\n", with: "\n") ?? ""
        #else
        ""
        #endif
    }
}
