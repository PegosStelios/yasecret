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
