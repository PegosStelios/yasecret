import XCTest
@testable import Yasecret

final class UnlockViewModelTests: XCTestCase {

    func testKeychainSaveAndLoad() throws {
        let service = KeychainService(account: "test-\(UUID().uuidString)")
        defer { service.delete() }

        service.save(password: "hunter2")
        let loaded = service.load()
        XCTAssertEqual(loaded, "hunter2")
    }

    func testKeychainLoadReturnsNilWhenAbsent() {
        let service = KeychainService(account: "test-nonexistent-\(UUID().uuidString)")
        XCTAssertNil(service.load())
    }

    func testKeychainDelete() {
        let service = KeychainService(account: "test-del-\(UUID().uuidString)")
        service.save(password: "pw")
        service.delete()
        XCTAssertNil(service.load())
    }

    func testUnlockViewModelUnlocksWithCorrectPassword() async throws {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        let dbPath = dir.appendingPathComponent("db.sqlite").path

        // Prime the DB first
        let _ = try YasecretSession(dbPath: dbPath, password: "correct")

        let appState = AppState()
        let vm = UnlockViewModel(appState: appState, dbPath: dbPath)
        vm.password = "correct"
        await vm.unlock()

        XCTAssertFalse(appState.isLocked)
        XCTAssertNotNil(appState.session)
    }

    func testUnlockViewModelSetsErrorOnWrongPassword() async throws {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        let dbPath = dir.appendingPathComponent("db.sqlite").path
        let _ = try YasecretSession(dbPath: dbPath, password: "correct")

        let appState = AppState()
        let vm = UnlockViewModel(appState: appState, dbPath: dbPath)
        vm.password = "wrong"
        await vm.unlock()

        XCTAssertTrue(appState.isLocked)
        XCTAssertNil(appState.session)
        XCTAssertNotNil(vm.errorMessage)
    }
}
