import Foundation

struct ServerConnection: Codable, Equatable, Sendable {
    var host: String
    var port: Int
    var tlsFingerprint: String
    var deviceID: String
    var deviceToken: String
    var isLocal: Bool
    var sshUser: String
    var sshKeyPath: String?

    var baseURL: URL {
        URL(string: "https://\(host):\(port)")!
    }
}

struct HealthResponse: Codable, Sendable {
    var version: String
    var os: String
    var arch: String
    var imapConnected: Bool
    var imapError: String
    var pairedDevices: Int
    var pendingAbuseCount: Int
    var tlsFingerprint: String

    enum CodingKeys: String, CodingKey {
        case version, os, arch
        case imapConnected = "imap_connected"
        case imapError = "imap_error"
        case pairedDevices = "paired_devices"
        case pendingAbuseCount = "pending_abuse_count"
        case tlsFingerprint = "tls_fingerprint"
    }
}

struct AppSettings: Codable, Equatable, Sendable {
    var imapHost: String = "imap.mail.me.com"
    var imapPort: Int = 993
    var imapUsername: String = ""
    var imapPassword: String?
    var aiProvider: String = "typesafe"
    var aiAPIKey: String?
    var aiModel: String = "jev-latest"
    var deleteEnabled: Bool = false
    var junkThreshold: Double = 0.85
    var deleteThreshold: Double = 0.95
    var abuseEnabled: Bool = true
    var abuseManualApproval: Bool = true
    var abuseMinConfidence: Double = 0.95
    var abuseCooldownDays: Int = 7

    var hasIMAPPassword: Bool?
    var hasAIAPIKey: Bool?

    enum CodingKeys: String, CodingKey {
        case imapHost = "imap_host"
        case imapPort = "imap_port"
        case imapUsername = "imap_username"
        case imapPassword = "imap_password"
        case aiProvider = "ai_provider"
        case aiAPIKey = "ai_api_key"
        case aiModel = "ai_model"
        case deleteEnabled = "delete_enabled"
        case junkThreshold = "junk_threshold"
        case deleteThreshold = "delete_threshold"
        case abuseEnabled = "abuse_enabled"
        case abuseManualApproval = "abuse_manual_approval"
        case abuseMinConfidence = "abuse_min_confidence"
        case abuseCooldownDays = "abuse_cooldown_days"
        case hasIMAPPassword = "has_imap_password"
        case hasAIAPIKey = "has_ai_api_key"
    }
}

struct Category: Codable, Identifiable, Equatable, Sendable {
    var id: String
    var name: String
    var description: String
    var enabled: Bool
    var builtin: Bool
    var abuseEligible: Bool
    var createdAt: String

    enum CodingKeys: String, CodingKey {
        case id, name, description, enabled, builtin
        case abuseEligible = "abuse_eligible"
        case createdAt = "created_at"
    }
}

struct CategoriesResponse: Codable, Sendable {
    var categories: [Category]
}

struct AllowlistEntry: Codable, Identifiable, Equatable, Sendable {
    var id: Int64
    var pattern: String
    var kind: String
    var builtin: Bool
    var createdAt: String

    enum CodingKeys: String, CodingKey {
        case id, pattern, kind, builtin
        case createdAt = "created_at"
    }
}

struct AllowlistResponse: Codable, Sendable {
    var entries: [AllowlistEntry]
}

struct DailyCategoryStat: Codable, Identifiable, Sendable {
    var day: String
    var categoryID: String
    var categoryName: String
    var count: Int

    var id: String { "\(day)-\(categoryID)" }

    var parsedDate: Date {
        let formatter = DateFormatter()
        formatter.dateFormat = "yyyy-MM-dd"
        formatter.timeZone = TimeZone(identifier: "UTC")
        return formatter.date(from: day) ?? Date()
    }

    enum CodingKeys: String, CodingKey {
        case day
        case categoryID = "category_id"
        case categoryName = "category_name"
        case count
    }
}

struct DailyStatsResponse: Codable, Sendable {
    var days: Int
    var totalBlocked: Int
    var stats: [DailyCategoryStat]

    enum CodingKeys: String, CodingKey {
        case days
        case totalBlocked = "total_blocked"
        case stats
    }
}

struct ScanMatch: Codable, Identifiable, Sendable {
    var mailbox: String?
    var uid: UInt32
    var sender: String
    var subject: String
    var emailDate: String
    var categoryID: String
    var confidence: Double
    var action: String

    var id: String { "\(mailbox ?? "INBOX")-\(uid)" }

    enum CodingKeys: String, CodingKey {
        case mailbox, uid, sender, subject, confidence, action
        case emailDate = "email_date"
        case categoryID = "category_id"
    }
}

struct ScanJob: Codable, Identifiable, Sendable {
    var id: String
    var dateRange: String
    var dryRun: Bool
    var ratePerSec: Double
    var status: String
    var currentMailbox: String?
    var totalMessages: Int
    var scannedMessages: Int
    var spamFound: Int
    var lastUID: UInt32
    var summary: [String: Int]
    var errorMsg: String
    var createdAt: String
    var updatedAt: String

    var progressFraction: Double {
        guard totalMessages > 0 else { return 0 }
        return min(1.0, Double(scannedMessages) / Double(totalMessages))
    }

    enum CodingKeys: String, CodingKey {
        case id, status, summary
        case dateRange = "date_range"
        case dryRun = "dry_run"
        case ratePerSec = "rate_per_sec"
        case currentMailbox = "current_mailbox"
        case totalMessages = "total_messages"
        case scannedMessages = "scanned_messages"
        case spamFound = "spam_found"
        case lastUID = "last_uid"
        case errorMsg = "error_msg"
        case createdAt = "created_at"
        case updatedAt = "updated_at"
    }
}

struct ScanJobEnvelope: Codable, Sendable {
    var job: ScanJob?
}

struct ScanMatchesResponse: Codable, Sendable {
    var matches: [ScanMatch]
}

struct JunkItem: Codable, Identifiable, Sendable {
    var uid: UInt32
    var sender: String
    var subject: String
    var emailDate: String
    var categoryID: String
    var confidence: Double

    var id: UInt32 { uid }

    enum CodingKeys: String, CodingKey {
        case uid, sender, subject, confidence
        case emailDate = "email_date"
        case categoryID = "category_id"
    }
}

struct JunkListing: Codable, Sendable {
    var mailbox: String
    var uidValidity: UInt32
    var items: [JunkItem]

    enum CodingKeys: String, CodingKey {
        case mailbox, items
        case uidValidity = "uid_validity"
    }
}

struct JunkDeleteResponse: Codable, Sendable {
    var deleted: Int
}

struct AbuseTarget: Codable, Equatable, Sendable {
    var address: String
    var kind: String
    var reason: String
}

struct AbuseQueueItem: Codable, Identifiable, Equatable, Sendable {
    var id: Int64
    var rootDomain: String
    var sendingIP: String
    var categoryID: String
    var confidence: Double
    var hitCount: Int
    var targets: [AbuseTarget]
    var redactedHeaders: String
    var subject: String
    var sender: String
    var repeatOffense: Bool
    var previousReportedAt: String?
    var status: String
    var createdAt: String
    var updatedAt: String

    var isSending: Bool { status == "sending" }

    enum CodingKeys: String, CodingKey {
        case id, confidence, targets, subject, sender, status
        case rootDomain = "root_domain"
        case sendingIP = "sending_ip"
        case categoryID = "category_id"
        case hitCount = "hit_count"
        case redactedHeaders = "redacted_headers"
        case repeatOffense = "repeat_offense"
        case previousReportedAt = "previous_reported_at"
        case createdAt = "created_at"
        case updatedAt = "updated_at"
    }
}

struct AbuseQueueResponse: Codable, Sendable {
    var items: [AbuseQueueItem]
}

struct AbuseDelivery: Codable, Equatable, Sendable {
    var address: String
    var kind: String
    var reason: String
    var ok: Bool
    var error: String?
}

struct AbuseHistoryEntry: Codable, Identifiable, Sendable {
    var id: Int64
    var rootDomain: String
    var categoryID: String
    var subject: String
    var sender: String
    var deliveries: [AbuseDelivery]
    var status: String
    var reportedAt: String

    enum CodingKeys: String, CodingKey {
        case id, subject, sender, deliveries, status
        case rootDomain = "root_domain"
        case categoryID = "category_id"
        case reportedAt = "reported_at"
    }
}

struct AbuseHistoryResponse: Codable, Sendable {
    var entries: [AbuseHistoryEntry]
}

struct MailingList: Codable, Identifiable, Equatable, Sendable {
    var sender: String
    var displayName: String
    var senderDomain: String
    var firstSeen: String
    var lastSeen: String
    var lastSubject: String
    var unsubscribedAt: String?
    var error: String?

    var id: String { sender }

    enum CodingKeys: String, CodingKey {
        case sender, error
        case displayName = "display_name"
        case senderDomain = "sender_domain"
        case firstSeen = "first_seen"
        case lastSeen = "last_seen"
        case lastSubject = "last_subject"
        case unsubscribedAt = "unsubscribed_at"
    }
}

struct MailingListsResponse: Codable, Sendable {
    var lists: [MailingList]
}

struct PairedDevice: Codable, Identifiable, Equatable, Sendable {
    var id: String
    var name: String
    var createdAt: String
    var lastSeenAt: String

    enum CodingKeys: String, CodingKey {
        case id, name
        case createdAt = "created_at"
        case lastSeenAt = "last_seen_at"
    }
}

struct DevicesResponse: Codable, Sendable {
    var devices: [PairedDevice]
}

struct PairRequestResponse: Codable, Sendable {
    var requestID: String
    var verificationCode: String
    var expiresAt: String

    enum CodingKeys: String, CodingKey {
        case requestID = "request_id"
        case verificationCode = "verification_code"
        case expiresAt = "expires_at"
    }
}

struct PairStatusResponse: Codable, Sendable {
    var status: String
    var deviceID: String?
    var token: String?

    enum CodingKeys: String, CodingKey {
        case status, token
        case deviceID = "device_id"
    }
}

struct PairRedeemResponse: Codable, Sendable {
    var deviceID: String
    var token: String

    enum CodingKeys: String, CodingKey {
        case deviceID = "device_id"
        case token
    }
}

struct IncomingPairRequest: Codable, Identifiable, Equatable, Sendable {
    var requestID: String
    var deviceName: String
    var verificationCode: String
    var expiresAt: String

    var id: String { requestID }

    enum CodingKeys: String, CodingKey {
        case requestID = "request_id"
        case deviceName = "device_name"
        case verificationCode = "verification_code"
        case expiresAt = "expires_at"
    }
}

struct ValidationResponse: Codable, Sendable {
    var ok: Bool
    var error: String
}

struct AbuseQueueEvent: Codable, Sendable {
    var pendingCount: Int

    enum CodingKeys: String, CodingKey {
        case pendingCount = "pending_count"
    }
}

struct DiscoveredHost: Identifiable, Hashable, Sendable {
    enum Source: String, Sendable {
        case local = "This Mac"
        case tailscale = "Tailscale"
        case bonjour = "Wi-Fi"
        case manual = "Manual"
    }

    var id: String { "\(source.rawValue)-\(address)" }
    var name: String
    var address: String
    var source: Source
    var osHint: String?
    var isLocal: Bool { source == .local }
}

struct SSHKeyFile: Identifiable, Hashable, Sendable {
    var id: String { path }
    var name: String
    var path: String
}
