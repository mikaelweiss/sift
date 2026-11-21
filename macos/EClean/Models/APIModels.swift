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
    var trashThreshold: Double = 0.85
    var deleteThreshold: Double = 0.95
    var abuseEnabled: Bool = true
    var abuseManualApproval: Bool = true
    var abuseMinConfidence: Double = 0.95
    var abuseCooldownDays: Int = 7
    var abuseSMTPMode: String = "icloud_alias"
    var abuseFromEmail: String = ""
    var abuseSMTPHost: String = "smtp.mail.me.com"
    var abuseSMTPPort: Int = 587
    var abuseSMTPUsername: String = ""
    var abuseSMTPPassword: String?

    var hasIMAPPassword: Bool?
    var hasAIAPIKey: Bool?
    var hasAbuseSMTPPassword: Bool?

    enum CodingKeys: String, CodingKey {
        case imapHost = "imap_host"
        case imapPort = "imap_port"
        case imapUsername = "imap_username"
        case imapPassword = "imap_password"
        case aiProvider = "ai_provider"
        case aiAPIKey = "ai_api_key"
        case aiModel = "ai_model"
        case deleteEnabled = "delete_enabled"
        case trashThreshold = "trash_threshold"
        case deleteThreshold = "delete_threshold"
        case abuseEnabled = "abuse_enabled"
        case abuseManualApproval = "abuse_manual_approval"
        case abuseMinConfidence = "abuse_min_confidence"
        case abuseCooldownDays = "abuse_cooldown_days"
        case abuseSMTPMode = "abuse_smtp_mode"
        case abuseFromEmail = "abuse_from_email"
        case abuseSMTPHost = "abuse_smtp_host"
        case abuseSMTPPort = "abuse_smtp_port"
        case abuseSMTPUsername = "abuse_smtp_username"
        case abuseSMTPPassword = "abuse_smtp_password"
        case hasIMAPPassword = "has_imap_password"
        case hasAIAPIKey = "has_ai_api_key"
        case hasAbuseSMTPPassword = "has_abuse_smtp_password"
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
    var createdAt: String

    enum CodingKeys: String, CodingKey {
        case id, pattern, kind
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

struct TrashItem: Codable, Identifiable, Sendable {
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

struct TrashListing: Codable, Sendable {
    var mailbox: String
    var uidValidity: UInt32
    var items: [TrashItem]

    enum CodingKeys: String, CodingKey {
        case mailbox, items
        case uidValidity = "uid_validity"
    }
}

struct TrashDeleteResponse: Codable, Sendable {
    var deleted: Int
}

struct AbuseQueueItem: Codable, Identifiable, Equatable, Sendable {
    var id: Int64
    var rootDomain: String
    var sendingIP: String
    var categoryID: String
    var confidence: Double
    var hitCount: Int
    var targets: [String]
    var redactedHeaders: String
    var subject: String
    var sender: String
    var repeatOffense: Bool
    var previousReportedAt: String?
    var createdAt: String
    var updatedAt: String

    enum CodingKeys: String, CodingKey {
        case id, confidence, targets, subject, sender
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

struct AbuseApproveResponse: Codable, Sendable {
    var status: String
    var error: String
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
