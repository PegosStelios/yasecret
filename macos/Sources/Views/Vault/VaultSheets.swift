import SwiftUI

/// Shared layout for the vault sheets: title, explanation, fields, error and two buttons.
private struct VaultSheetFrame<Fields: View>: View {
    let title: String
    let message: String
    let action: String
    let canSubmit: Bool
    let working: Bool
    let error: String?
    let submit: () -> Void
    @ViewBuilder let fields: Fields
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        VStack(alignment: .leading, spacing: Layout.sheetSpacing) {
            Text(title).font(.title3.bold())
            Text(message)
                .font(.callout)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            fields
            SheetError(text: error)
            HStack {
                if working { ProgressView().controlSize(.small) }
                Spacer()
                Button("Cancel", role: .cancel) { dismiss() }
                    .keyboardShortcut(.cancelAction)
                    .disabled(working)
                Button(action, action: submit)
                    .keyboardShortcut(.defaultAction)
                    .buttonStyle(.borderedProminent)
                    .disabled(!canSubmit || working)
            }
        }
        .padding(20)
        .frame(width: Layout.sheetMedium)
        .interactiveDismissDisabled(working)
    }
}

private func passwordsProblem(_ new: String, _ confirm: String) -> String? {
    if new.isEmpty || confirm.isEmpty { return nil }
    return new == confirm ? nil : "The new passwords don't match"
}

struct ChangePasswordSheet: View {
    @Environment(AppState.self) private var appState
    @Environment(\.dismiss) private var dismiss
    @State private var current = ""
    @State private var new = ""
    @State private var confirm = ""
    @State private var working = false
    @State private var error: String?

    var body: some View {
        VaultSheetFrame(
            title: "Change Master Password",
            message: "The vault is re-encrypted with the new password. Your recovery key keeps working, and backups made earlier still need the password they were made with.",
            action: "Change Password",
            canSubmit: !current.isEmpty && !new.isEmpty && new == confirm,
            working: working,
            error: error ?? passwordsProblem(new, confirm),
            submit: change
        ) {
            SecureField("Current password", text: $current).textFieldStyle(.roundedBorder)
            SecureField("New password", text: $new).textFieldStyle(.roundedBorder)
            SecureField("Repeat new password", text: $confirm).textFieldStyle(.roundedBorder)
        }
    }

    private func change() {
        working = true
        error = nil
        Task {
            do {
                try await appState.changePassword(old: current, new: new)
                dismiss()
            } catch FfiError.WrongPassword {
                error = "The current password isn't right"
            } catch {
                self.error = userMessage(error)
            }
            working = false
        }
    }
}

struct RecoveryKeySheet: View {
    let session: YasecretSession
    @Environment(\.dismiss) private var dismiss
    @State private var key: String?
    @State private var error: String?
    @State private var copied = false
    @State private var hasExisting = false

    var body: some View {
        VStack(alignment: .leading, spacing: Layout.sheetSpacing) {
            Text("Recovery Key").font(.title3.bold())
            if let key {
                Text("Write this down or store it in a password manager, away from this Mac. It's shown only once.")
                    .font(.callout)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
                HStack(alignment: .top) {
                    Text(key)
                        .font(.system(.body, design: .monospaced))
                        .textSelection(.enabled)
                        .fixedSize(horizontal: false, vertical: true)
                        .frame(maxWidth: .infinity, alignment: .leading)
                    Button {
                        Clipboard.copy(key, sensitive: true)
                        copied = true
                    } label: {
                        Label(copied ? "Copied" : "Copy", systemImage: copied ? "checkmark" : "doc.on.doc")
                    }
                }
                .padding(10)
                .background(.quaternary.opacity(0.6), in: RoundedRectangle(cornerRadius: 8))
                Text("Anyone with this key and your vault files can reset the master password.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            } else {
                Text(hasExisting
                     ? "This vault has a recovery key. Making a new one retires the old key."
                     : "A recovery key lets you set a new master password if you forget it. Without one, a forgotten password means losing the vault.")
                    .font(.callout)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            SheetError(text: error)
            HStack {
                Spacer()
                if key == nil {
                    Button("Cancel", role: .cancel) { dismiss() }.keyboardShortcut(.cancelAction)
                    Button(hasExisting ? "Make New Key" : "Make Recovery Key", action: make)
                        .keyboardShortcut(.defaultAction)
                        .buttonStyle(.borderedProminent)
                } else {
                    Button("I've Saved It") { dismiss() }
                        .keyboardShortcut(.defaultAction)
                        .buttonStyle(.borderedProminent)
                }
            }
        }
        .padding(20)
        .frame(width: Layout.sheetMedium)
        .interactiveDismissDisabled(key != nil)
        .onAppear { hasExisting = session.hasRecoveryKey() }
    }

    private func make() {
        do { key = try session.createRecoveryKey() } catch { self.error = userMessage(error) }
    }
}

struct ForgotPasswordSheet: View {
    let onReset: (String) async -> Void
    @Environment(\.dismiss) private var dismiss
    @State private var key = ""
    @State private var new = ""
    @State private var confirm = ""
    @State private var working = false
    @State private var error: String?
    private let available = vaultHasRecoveryKey(dbPath: VaultLocation.dbPath)

    var body: some View {
        VaultSheetFrame(
            title: "Reset Master Password",
            message: available
                ? "Enter your recovery key and choose a new master password."
                : "This vault has no recovery key, so the master password can't be reset. If you have a backup, you can restore it instead.",
            action: "Reset Password",
            canSubmit: available && !key.isEmpty && !new.isEmpty && new == confirm,
            working: working,
            error: error ?? passwordsProblem(new, confirm),
            submit: reset
        ) {
            if available {
                TextField("Recovery key", text: $key)
                    .textFieldStyle(.roundedBorder)
                    .font(.system(.body, design: .monospaced))
                SecureField("New password", text: $new).textFieldStyle(.roundedBorder)
                SecureField("Repeat new password", text: $confirm).textFieldStyle(.roundedBorder)
            }
        }
    }

    private func reset() {
        working = true
        error = nil
        let (path, key, new) = (VaultLocation.dbPath, key, new)
        Task {
            do {
                try await Task.detached { try recoverVault(dbPath: path, recoveryKey: key, newPassword: new) }.value
                dismiss()
                await onReset(new)
            } catch {
                self.error = userMessage(error)
            }
            working = false
        }
    }
}

struct RestoreBackupSheet: View {
    let file: URL
    let replacesVault: Bool
    let onRestored: (String) async -> Void
    @Environment(\.dismiss) private var dismiss
    @State private var password = ""
    @State private var working = false
    @State private var error: String?

    var body: some View {
        VaultSheetFrame(
            title: "Restore from Backup",
            message: "Restore “\(file.lastPathComponent)” using the master password the vault had when it was backed up."
                + (replacesVault ? " This replaces the vault on this Mac." : ""),
            action: replacesVault ? "Replace and Restore" : "Restore",
            canSubmit: !password.isEmpty,
            working: working,
            error: error,
            submit: restore
        ) {
            SecureField("Backup's master password", text: $password).textFieldStyle(.roundedBorder)
        }
    }

    private func restore() {
        working = true
        error = nil
        let (backup, path, password) = (file.path, VaultLocation.dbPath, password)
        Task {
            do {
                try await Task.detached { try restoreVaultBackup(backupPath: backup, dbPath: path, password: password) }.value
                dismiss()
                await onRestored(password)
            } catch FfiError.WrongPassword {
                error = "That password doesn't open this backup"
            } catch {
                self.error = userMessage(error)
            }
            working = false
        }
    }
}
