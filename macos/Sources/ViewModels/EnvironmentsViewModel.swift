import Foundation

@Observable
final class EnvironmentsViewModel {
    var environments: [FfiEnvironment] = []
    var selectedEnvId: String?
    var errorMessage: String?

    func load(projectId: String, session: YasecretSession) {
        do {
            environments = try session.listEnvironments(projectId: projectId)
            if selectedEnvId == nil { selectedEnvId = environments.first?.id }
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    func createEnvironment(projectId: String, name: String, session: YasecretSession) {
        do {
            let e = try session.createEnvironment(projectId: projectId, name: name)
            environments.append(e)
            selectedEnvId = e.id
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    func renameEnvironment(id: String, newName: String, session: YasecretSession) {
        do {
            try session.renameEnvironment(envId: id, newName: newName)
            if let idx = environments.firstIndex(where: { $0.id == id }) {
                environments[idx] = FfiEnvironment(id: environments[idx].id, projectId: environments[idx].projectId, name: newName)
            }
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    func deleteEnvironment(id: String, session: YasecretSession) {
        do {
            try session.deleteEnvironment(envId: id)
            environments.removeAll { $0.id == id }
            if selectedEnvId == id { selectedEnvId = environments.first?.id }
        } catch {
            errorMessage = error.localizedDescription
        }
    }
}
