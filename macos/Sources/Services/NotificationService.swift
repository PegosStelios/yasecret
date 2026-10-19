import UserNotifications

final class NotificationService {
    static let shared = NotificationService()

    func requestPermission() {
        UNUserNotificationCenter.current().requestAuthorization(options: [.alert, .sound]) { _, _ in }
    }

    /// At most one reminder per variable per day.
    func notifyExpiring(_ items: [(id: String, label: String, expired: Bool)]) {
        let defaults = UserDefaults.standard
        let today = Calendar.current.startOfDay(for: Date()).timeIntervalSince1970
        let fresh = items.filter { defaults.double(forKey: "expiry-reminded-\($0.id)") < today }
        guard !fresh.isEmpty else { return }
        fresh.forEach { defaults.set(today, forKey: "expiry-reminded-\($0.id)") }
        let content = UNMutableNotificationContent()
        content.title = fresh.contains(where: \.expired) ? "Variables have expired" : "Variables expire soon"
        content.body = fresh.prefix(3).map(\.label).joined(separator: ", ") + (fresh.count > 3 ? " and \(fresh.count - 3) more" : "") + ". Rotate them in Yasecret."
        content.sound = .default
        UNUserNotificationCenter.current().add(UNNotificationRequest(identifier: "expiry-\(UUID().uuidString)", content: content, trigger: nil))
    }

    func notifyMcpAccess() {
        let content = UNMutableNotificationContent()
        content.title = "Yasecret"
        content.body = "Claude Code connected. MCP access granted."
        content.sound = .default
        let request = UNNotificationRequest(
            identifier: "mcp-tofu-\(UUID().uuidString)",
            content: content,
            trigger: nil
        )
        UNUserNotificationCenter.current().add(request)
    }
}
