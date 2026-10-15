import Foundation

@Observable
final class SecretsViewModel {
    var secrets: [FfiSecret] = []
    var errorMessage: String?

    func load(envId: String, session: YasecretSession) {
        do {
            secrets = try session.listSecrets(envId: envId)
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    func createSecret(projectId: String, envId: String, key: String, value: String,
                      expiresAt: Int64?, session: YasecretSession) {
        errorMessage = nil
        do {
            let s = try session.createSecret(
                projectId: projectId, envId: envId, key: key, value: value, expiresAt: expiresAt)
            secrets.append(s)
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    func updateSecret(projectId: String, secretId: String, newValue: String, session: YasecretSession) {
        do {
            try session.updateSecret(projectId: projectId, secretId: secretId, newValue: newValue)
            if let envId = secrets.first?.envId {
                secrets = try session.listSecrets(envId: envId)
            }
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    func deleteSecret(id: String, session: YasecretSession) {
        do {
            try session.deleteSecret(secretId: id)
            secrets.removeAll { $0.id == id }
        } catch {
            errorMessage = error.localizedDescription
        }
    }
}
