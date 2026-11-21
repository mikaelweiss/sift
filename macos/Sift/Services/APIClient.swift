import CryptoKit
import Foundation
import Security

final class PinnedSessionDelegate: NSObject, URLSessionDelegate, URLSessionTaskDelegate {
    private let expectedFingerprint: String?

    init(expectedFingerprint: String?) {
        self.expectedFingerprint = expectedFingerprint?
            .lowercased()
            .replacingOccurrences(of: ":", with: "")
            .trimmingCharacters(in: .whitespacesAndNewlines)
    }

    func urlSession(
        _ session: URLSession,
        didReceive challenge: URLAuthenticationChallenge,
        completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void
    ) {
        handleChallenge(challenge, completionHandler: completionHandler)
    }

    func urlSession(
        _ session: URLSession,
        task: URLSessionTask,
        didReceive challenge: URLAuthenticationChallenge,
        completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void
    ) {
        handleChallenge(challenge, completionHandler: completionHandler)
    }

    private func handleChallenge(
        _ challenge: URLAuthenticationChallenge,
        completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void
    ) {
        guard challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust,
              let trust = challenge.protectionSpace.serverTrust else {
            completionHandler(.performDefaultHandling, nil)
            return
        }

        guard let chain = SecTrustCopyCertificateChain(trust) as? [SecCertificate],
              let leaf = chain.first else {
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }

        let der = SecCertificateCopyData(leaf) as Data
        let digest = SHA256.hash(data: der)
        let hex = digest.map { String(format: "%02x", $0) }.joined()

        if let expected = expectedFingerprint, !expected.isEmpty {
            if hex == expected {
                completionHandler(.useCredential, URLCredential(trust: trust))
            } else {
                completionHandler(.cancelAuthenticationChallenge, nil)
            }
        } else {
            completionHandler(.useCredential, URLCredential(trust: trust))
        }
    }
}

enum APIClientError: LocalizedError {
    case httpError(Int, String)
    case invalidResponse

    var errorDescription: String? {
        switch self {
        case .httpError(let code, let message):
            return message.isEmpty ? "Server returned HTTP \(code)" : message
        case .invalidResponse:
            return "Invalid server response"
        }
    }
}

final class APIClient {
    let baseURL: URL
    let token: String?
    let tlsFingerprint: String?
    private let session: URLSession
    private let delegate: PinnedSessionDelegate

    init(baseURL: URL, token: String?, tlsFingerprint: String?) {
        self.baseURL = baseURL
        self.token = token
        self.tlsFingerprint = tlsFingerprint
        let delegate = PinnedSessionDelegate(expectedFingerprint: tlsFingerprint)
        self.delegate = delegate
        let config = URLSessionConfiguration.default
        config.timeoutIntervalForRequest = 30
        self.session = URLSession(configuration: config, delegate: delegate, delegateQueue: nil)
    }

    convenience init(connection: ServerConnection) {
        self.init(baseURL: connection.baseURL, token: connection.deviceToken, tlsFingerprint: connection.tlsFingerprint)
    }

    private func send<T: Decodable>(
        _ method: String,
        path: String,
        body: Encodable? = nil,
        authenticated: Bool = true
    ) async throws -> T {
        let data = try await sendRaw(method, path: path, body: body, authenticated: authenticated)
        return try JSONDecoder().decode(T.self, from: data)
    }

    @discardableResult
    private func sendRaw(
        _ method: String,
        path: String,
        body: Encodable? = nil,
        authenticated: Bool = true
    ) async throws -> Data {
        guard let url = URL(string: path, relativeTo: baseURL) else {
            throw APIClientError.invalidResponse
        }
        var request = URLRequest(url: url)
        request.httpMethod = method
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        if authenticated, let token, !token.isEmpty {
            request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        }
        if let body {
            request.setValue("application/json", forHTTPHeaderField: "Content-Type")
            request.httpBody = try JSONEncoder().encode(AnyEncodable(body))
        }

        let (data, response) = try await session.data(for: request)
        guard let http = response as? HTTPURLResponse else {
            throw APIClientError.invalidResponse
        }
        guard (200...299).contains(http.statusCode) else {
            let errText = (try? JSONDecoder().decode([String: String].self, from: data))?["error"]
                ?? String(data: data, encoding: .utf8)
                ?? ""
            throw APIClientError.httpError(http.statusCode, errText)
        }
        return data
    }

    func health() async throws -> HealthResponse {
        try await send("GET", path: "/api/health", authenticated: false)
    }

    func requestPair(deviceName: String) async throws -> PairRequestResponse {
        try await send("POST", path: "/api/pair/request", body: ["device_name": deviceName], authenticated: false)
    }

    func pairStatus(requestID: String) async throws -> PairStatusResponse {
        try await send("GET", path: "/api/pair/status/\(requestID)", authenticated: false)
    }

    func approvePair(requestID: String, approve: Bool) async throws {
        struct Payload: Encodable {
            let request_id: String
            let approve: Bool
        }
        _ = try await sendRaw("POST", path: "/api/pair/approve", body: Payload(request_id: requestID, approve: approve))
    }

    func redeemPair(code: String, deviceName: String) async throws -> PairRedeemResponse {
        try await send("POST", path: "/api/pair/redeem", body: ["code": code, "device_name": deviceName], authenticated: false)
    }

    func listDevices() async throws -> [PairedDevice] {
        let resp: DevicesResponse = try await send("GET", path: "/api/devices")
        return resp.devices
    }

    func revokeDevice(id: String) async throws {
        _ = try await sendRaw("DELETE", path: "/api/devices/\(id)")
    }

    func dailyStats(days: Int) async throws -> DailyStatsResponse {
        try await send("GET", path: "/api/stats/daily?days=\(days)")
    }

    func getSettings() async throws -> AppSettings {
        try await send("GET", path: "/api/settings")
    }

    func updateSettings(_ settings: AppSettings) async throws -> AppSettings {
        try await send("PUT", path: "/api/settings", body: settings)
    }

    func validateIMAP(host: String, port: Int, username: String, password: String) async throws -> ValidationResponse {
        struct Payload: Encodable {
            let host: String
            let port: Int
            let username: String
            let password: String
        }
        return try await send("POST", path: "/api/validate/imap", body: Payload(host: host, port: port, username: username, password: password))
    }

    func validateAI(provider: String, apiKey: String, model: String) async throws -> ValidationResponse {
        struct Payload: Encodable {
            let provider: String
            let api_key: String
            let model: String
        }
        return try await send("POST", path: "/api/validate/ai", body: Payload(provider: provider, api_key: apiKey, model: model))
    }

    func listCategories() async throws -> [Category] {
        let resp: CategoriesResponse = try await send("GET", path: "/api/categories")
        return resp.categories
    }

    func createCategory(name: String, description: String, enabled: Bool, abuseEligible: Bool) async throws -> Category {
        struct Payload: Encodable {
            let name: String
            let description: String
            let enabled: Bool
            let abuse_eligible: Bool
        }
        return try await send("POST", path: "/api/categories", body: Payload(name: name, description: description, enabled: enabled, abuse_eligible: abuseEligible))
    }

    func updateCategory(_ category: Category) async throws -> Category {
        struct Payload: Encodable {
            let name: String
            let description: String
            let enabled: Bool
            let abuse_eligible: Bool
        }
        return try await send("PUT", path: "/api/categories/\(category.id)", body: Payload(name: category.name, description: category.description, enabled: category.enabled, abuse_eligible: category.abuseEligible))
    }

    func deleteCategory(id: String) async throws {
        _ = try await sendRaw("DELETE", path: "/api/categories/\(id)")
    }

    func listAllowlist() async throws -> [AllowlistEntry] {
        let resp: AllowlistResponse = try await send("GET", path: "/api/allowlist")
        return resp.entries
    }

    func addAllowlist(pattern: String, kind: String) async throws -> AllowlistEntry {
        try await send("POST", path: "/api/allowlist", body: ["pattern": pattern, "kind": kind])
    }

    func deleteAllowlist(id: Int64) async throws {
        _ = try await sendRaw("DELETE", path: "/api/allowlist/\(id)")
    }

    func latestScan() async throws -> ScanJob? {
        let resp: ScanJobEnvelope = try await send("GET", path: "/api/scans/latest")
        return resp.job
    }

    func startScan(dateRange: String, dryRun: Bool, ratePerSec: Double) async throws -> ScanJob {
        struct Payload: Encodable {
            let date_range: String
            let dry_run: Bool
            let rate_per_sec: Double
        }
        let resp: ScanJobEnvelope = try await send("POST", path: "/api/scans", body: Payload(date_range: dateRange, dry_run: dryRun, rate_per_sec: ratePerSec))
        guard let job = resp.job else { throw APIClientError.invalidResponse }
        return job
    }

    func pauseScan(id: String) async throws -> ScanJob {
        let resp: ScanJobEnvelope = try await send("POST", path: "/api/scans/\(id)/pause")
        guard let job = resp.job else { throw APIClientError.invalidResponse }
        return job
    }

    func resumeScan(id: String) async throws -> ScanJob {
        let resp: ScanJobEnvelope = try await send("POST", path: "/api/scans/\(id)/resume")
        guard let job = resp.job else { throw APIClientError.invalidResponse }
        return job
    }

    func cancelScan(id: String) async throws -> ScanJob {
        let resp: ScanJobEnvelope = try await send("POST", path: "/api/scans/\(id)/cancel")
        guard let job = resp.job else { throw APIClientError.invalidResponse }
        return job
    }

    func applyScan(id: String) async throws -> ScanJob {
        let resp: ScanJobEnvelope = try await send("POST", path: "/api/scans/\(id)/apply")
        guard let job = resp.job else { throw APIClientError.invalidResponse }
        return job
    }

    func scanMatches(id: String) async throws -> [ScanMatch] {
        let resp: ScanMatchesResponse = try await send("GET", path: "/api/scans/\(id)/matches")
        return resp.matches
    }

    func listJunk() async throws -> JunkListing {
        try await send("GET", path: "/api/junk")
    }

    func deleteFromJunk(uidValidity: UInt32, uids: [UInt32]) async throws -> Int {
        struct Payload: Encodable {
            let uid_validity: UInt32
            let uids: [UInt32]
        }
        let resp: JunkDeleteResponse = try await send("POST", path: "/api/junk/delete", body: Payload(uid_validity: uidValidity, uids: uids))
        return resp.deleted
    }

    func listMailingLists() async throws -> [MailingList] {
        let resp: MailingListsResponse = try await send("GET", path: "/api/mailing-lists")
        return resp.lists
    }

    func unsubscribe(sender: String) async throws -> MailingList {
        try await send("POST", path: "/api/mailing-lists/unsubscribe", body: ["sender": sender])
    }

    func abuseHistory() async throws -> [AbuseHistoryEntry] {
        let resp: AbuseHistoryResponse = try await send("GET", path: "/api/abuse/history")
        return resp.entries
    }

    func listAbuseQueue() async throws -> [AbuseQueueItem] {
        let resp: AbuseQueueResponse = try await send("GET", path: "/api/abuse/queue")
        return resp.items
    }

    func approveAbuse(id: Int64) async throws {
        _ = try await sendRaw("POST", path: "/api/abuse/\(id)/approve")
    }

    func dismissAbuse(id: Int64) async throws {
        _ = try await sendRaw("POST", path: "/api/abuse/\(id)/dismiss")
    }
}

private struct AnyEncodable: Encodable {
    private let encodeClosure: (Encoder) throws -> Void

    init(_ wrapped: Encodable) {
        self.encodeClosure = { try wrapped.encode(to: $0) }
    }

    func encode(to encoder: Encoder) throws {
        try encodeClosure(encoder)
    }
}
