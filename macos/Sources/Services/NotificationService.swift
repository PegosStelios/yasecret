import UserNotifications

final class NotificationService {
    static let shared = NotificationService()

    func requestPermission() {
        UNUserNotificationCenter.current().requestAuthorization(options: [.alert, .sound]) { _, _ in }
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
