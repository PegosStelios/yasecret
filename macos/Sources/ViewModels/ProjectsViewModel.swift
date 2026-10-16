import Foundation

@Observable
final class ProjectsViewModel {
    static let defaultEnvironments = ["development", "staging", "production"]

    var projects: [FfiProject] = []
    var sharedIds: Set<String> = []
    var selectedProjectId: String?
    var errorMessage: String?

    func load(session: YasecretSession) {
        do {
            projects = try session.listProjects()
            sharedIds = Set((try? session.sharedProjectIds()) ?? [])
            if let sel = selectedProjectId, !projects.contains(where: { $0.id == sel }) {
                selectedProjectId = projects.first?.id
            }
        } catch {
            errorMessage = userMessage(error)
        }
    }

    func createProject(name: String, withDefaultEnvironments: Bool = false, session: YasecretSession) {
        do {
            let p = try session.createProject(name: name, description: nil)
            if withDefaultEnvironments {
                for env in Self.defaultEnvironments {
                    _ = try session.createEnvironment(projectId: p.id, name: env)
                }
            }
            projects.append(p)
            selectedProjectId = p.id
        } catch {
            errorMessage = userMessage(error)
        }
    }

    func renameProject(id: String, newName: String, session: YasecretSession) {
        do {
            try session.renameProject(projectId: id, newName: newName)
            if let idx = projects.firstIndex(where: { $0.id == id }) {
                projects[idx].name = newName
            }
        } catch {
            errorMessage = userMessage(error)
        }
    }

    func deleteProject(id: String, session: YasecretSession) {
        do {
            try session.deleteProject(projectId: id)
            projects.removeAll { $0.id == id }
            if selectedProjectId == id { selectedProjectId = nil }
        } catch {
            errorMessage = userMessage(error)
        }
    }
}
