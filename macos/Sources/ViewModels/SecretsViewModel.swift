import Foundation

@Observable
final class SecretsViewModel {
    var secrets: [FfiSecret] = []
    var errorMessage: String?
    var searchText = ""

    var filtered: [FfiSecret] {
        let q = searchText.trimmingCharacters(in: .whitespaces)
        guard !q.isEmpty else { return secrets }
        return secrets.filter { $0.key.localizedCaseInsensitiveContains(q) }
    }

    func load(envId: String, session: YasecretSession) {
        do {
            secrets = try session.listSecrets(envId: envId)
        } catch {
            errorMessage = userMessage(error)
        }
    }

    @discardableResult
    func createSecret(projectId: String, envId: String, key: String, value: String,
                      isSecret: Bool = true, expiresAt: Int64? = nil,
                      session: YasecretSession) -> Bool {
        errorMessage = nil
        do {
            _ = try session.createSecret(
                projectId: projectId, envId: envId, key: key, value: value,
                expiresAt: expiresAt, isSecret: isSecret)
            secrets = try session.listSecrets(envId: envId)
            return true
        } catch {
            errorMessage = userMessage(error)
            return false
        }
    }

    /// Pass nil for anything that should stay unchanged.
    @discardableResult
    func editSecret(projectId: String, secret: FfiSecret, newKey: String?, newValue: String?,
                    isSecret: Bool?, session: YasecretSession) -> Bool {
        errorMessage = nil
        do {
            try session.editSecret(
                projectId: projectId, secretId: secret.id,
                newKey: newKey == secret.key ? nil : newKey,
                newValue: newValue,
                isSecret: isSecret == secret.isSecret ? nil : isSecret)
            secrets = try session.listSecrets(envId: secret.envId)
            return true
        } catch {
            errorMessage = userMessage(error)
            return false
        }
    }

    @discardableResult
    func setExpiry(projectId: String, secret: FfiSecret, expiresAt: Int64?, session: YasecretSession) -> Bool {
        do {
            try session.setExpiry(projectId: projectId, secretId: secret.id, expiresAt: expiresAt)
            secrets = try session.listSecrets(envId: secret.envId)
            return true
        } catch {
            errorMessage = userMessage(error)
            return false
        }
    }

    func updateSecret(projectId: String, secretId: String, newValue: String, session: YasecretSession) {
        do {
            try session.updateSecret(projectId: projectId, secretId: secretId, newValue: newValue)
            if let envId = secrets.first?.envId {
                secrets = try session.listSecrets(envId: envId)
            }
        } catch {
            errorMessage = userMessage(error)
        }
    }

    func deleteSecret(id: String, session: YasecretSession) {
        do {
            try session.deleteSecret(secretId: id)
            secrets.removeAll { $0.id == id }
        } catch {
            errorMessage = userMessage(error)
        }
    }
}
