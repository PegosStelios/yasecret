import Foundation

@Observable
final class EnvironmentsViewModel {
    var environments: [FfiEnvironment] = []
    var selectedEnvId: String?
    var errorMessage: String?

    var selectedEnvironment: FfiEnvironment? {
        environments.first { $0.id == selectedEnvId }
    }

    func load(projectId: String, session: YasecretSession) {
        do {
            environments = try session.listEnvironments(projectId: projectId)
            if selectedEnvId == nil || !environments.contains(where: { $0.id == selectedEnvId }) {
                selectedEnvId = environments.first?.id
            }
        } catch {
            errorMessage = userMessage(error)
        }
    }

    func createEnvironment(projectId: String, name: String, session: YasecretSession) {
        do {
            let e = try session.createEnvironment(projectId: projectId, name: name)
            environments.append(e)
            selectedEnvId = e.id
        } catch {
            errorMessage = userMessage(error)
        }
    }

    func cloneEnvironment(id: String, newName: String, session: YasecretSession) {
        do {
            let e = try session.cloneEnvironment(envId: id, newName: newName)
            environments.append(e)
            selectedEnvId = e.id
        } catch {
            errorMessage = userMessage(error)
        }
    }

    func renameEnvironment(id: String, newName: String, session: YasecretSession) {
        do {
            try session.renameEnvironment(envId: id, newName: newName)
            if let idx = environments.firstIndex(where: { $0.id == id }) {
                environments[idx].name = newName
            }
        } catch {
            errorMessage = userMessage(error)
        }
    }

    func deleteEnvironment(id: String, session: YasecretSession) {
        do {
            try session.deleteEnvironment(envId: id)
            environments.removeAll { $0.id == id }
            if selectedEnvId == id { selectedEnvId = environments.first?.id }
        } catch {
            errorMessage = userMessage(error)
        }
    }
}
