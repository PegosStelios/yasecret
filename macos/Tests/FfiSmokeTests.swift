import XCTest
@testable import Yasecret

final class FfiSmokeTests: XCTestCase {

    func testDefaultDbPathIsNonEmpty() throws {
        let path = defaultDbPath()
        XCTAssertFalse(path.isEmpty)
        XCTAssertTrue(path.hasSuffix("db.sqlite"), "expected db.sqlite, got: \(path)")
    }

    func testSessionWrongPasswordThrows() throws {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }

        let dbPath = dir.appendingPathComponent("db.sqlite").path

        // Create DB with correct password first (salt is auto-created)
        let _ = try YasecretSession(dbPath: dbPath, password: "correct")

        XCTAssertThrowsError(
            try YasecretSession(dbPath: dbPath, password: "wrong")
        ) { error in
            guard let ffiErr = error as? FfiError else {
                XCTFail("Expected FfiError, got \(error)"); return
            }
            if case .WrongPassword = ffiErr { } else {
                XCTFail("Expected WrongPassword, got \(ffiErr)")
            }
        }
    }

    func testEndToEndProjectEnvSecret() throws {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }

        let session = try YasecretSession(
            dbPath: dir.appendingPathComponent("db.sqlite").path,
            password: "pw"
        )
        let proj = try session.createProject(name: "app", description: nil)
        let env = try session.createEnvironment(projectId: proj.id, name: "dev")
        let _ = try session.createSecret(projectId: proj.id, envId: env.id,
                                         key: "TOKEN", value: "abc", expiresAt: nil)

        let secrets = try session.listSecrets(envId: env.id)
        XCTAssertEqual(secrets.count, 1)
        XCTAssertEqual(secrets[0].key, "TOKEN")
    }
}
