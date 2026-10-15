import XCTest
@testable import Yasecret

final class SecretsViewModelTests: XCTestCase {

    private func makeSession() throws -> (YasecretSession, String, String) {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        let session = try YasecretSession(
            dbPath: dir.appendingPathComponent("db.sqlite").path,
            password: "pw"
        )
        let proj = try session.createProject(name: "app", description: nil)
        let env = try session.createEnvironment(projectId: proj.id, name: "dev")
        return (session, proj.id, env.id)
    }

    func testCreateSecretAppearsInList() throws {
        let (session, projId, envId) = try makeSession()
        let vm = SecretsViewModel()
        let _ = try session.createSecret(
            projectId: projId, envId: envId, key: "MY_KEY", value: "val", expiresAt: nil)
        vm.load(envId: envId, session: session)
        XCTAssertEqual(vm.secrets.count, 1)
        XCTAssertEqual(vm.secrets[0].key, "MY_KEY")
    }

    func testGetPlaintextReturnsValue() throws {
        let (session, projId, envId) = try makeSession()
        let secret = try session.createSecret(
            projectId: projId, envId: envId, key: "PW", value: "secret!", expiresAt: nil)
        let val = try session.getSecretPlaintext(projectId: projId, secretId: secret.id)
        XCTAssertEqual(val, "secret!")
    }

    func testDeleteSecretRemovedFromList() throws {
        let (session, projId, envId) = try makeSession()
        let secret = try session.createSecret(
            projectId: projId, envId: envId, key: "DEL", value: "bye", expiresAt: nil)
        let vm = SecretsViewModel()
        vm.load(envId: envId, session: session)
        XCTAssertEqual(vm.secrets.count, 1)
        vm.deleteSecret(id: secret.id, session: session)
        XCTAssertEqual(vm.secrets.count, 0)
    }

    func testUpdateSecretChangesValue() throws {
        let (session, projId, envId) = try makeSession()
        let secret = try session.createSecret(
            projectId: projId, envId: envId, key: "K", value: "old", expiresAt: nil)
        try session.updateSecret(projectId: projId, secretId: secret.id, newValue: "new")
        let val = try session.getSecretPlaintext(projectId: projId, secretId: secret.id)
        XCTAssertEqual(val, "new")
    }
}
