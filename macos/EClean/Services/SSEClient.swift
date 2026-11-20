import Foundation

enum SSEEvent: Sendable {
    case health(HealthResponse)
    case emailProcessed
    case pairRequest(IncomingPairRequest)
    case scanProgress(ScanJob)
    case abuseQueue(Int)
}

final class SSEClient {
    private var task: Task<Void, Never>?

    func start(
        connection: ServerConnection,
        onEvent: @escaping @Sendable (SSEEvent) -> Void,
        onConnectionChanged: @escaping @Sendable (Bool) -> Void
    ) {
        stop()
        let delegate = PinnedSessionDelegate(expectedFingerprint: connection.tlsFingerprint)
        let config = URLSessionConfiguration.default
        config.timeoutIntervalForRequest = .infinity
        config.timeoutIntervalForResource = .infinity
        let session = URLSession(configuration: config, delegate: delegate, delegateQueue: nil)

        task = Task {
            var backoffSeconds: UInt64 = 1
            while !Task.isCancelled {
                do {
                    guard let url = URL(string: "/api/events", relativeTo: connection.baseURL) else { return }
                    var req = URLRequest(url: url)
                    req.setValue("Bearer \(connection.deviceToken)", forHTTPHeaderField: "Authorization")
                    req.setValue("text/event-stream", forHTTPHeaderField: "Accept")

                    let (bytes, response) = try await session.bytes(for: req)
                    guard let http = response as? HTTPURLResponse, http.statusCode == 200 else {
                        onConnectionChanged(false)
                        try await Task.sleep(nanoseconds: backoffSeconds * 1_000_000_000)
                        backoffSeconds = min(backoffSeconds * 2, 30)
                        continue
                    }

                    onConnectionChanged(true)
                    backoffSeconds = 1

                    var currentEvent = ""
                    var dataLines: [String] = []

                    for try await line in bytes.lines {
                        if Task.isCancelled { break }
                        if line.isEmpty {
                            if !currentEvent.isEmpty && !dataLines.isEmpty {
                                let payload = dataLines.joined(separator: "\n")
                                if let parsed = Self.decodeEvent(name: currentEvent, payload: payload) {
                                    onEvent(parsed)
                                }
                            }
                            currentEvent = ""
                            dataLines = []
                            continue
                        }
                        if line.hasPrefix(":") { continue }
                        if line.hasPrefix("event:") {
                            currentEvent = line.dropFirst(6).trimmingCharacters(in: .whitespaces)
                        } else if line.hasPrefix("data:") {
                            dataLines.append(line.dropFirst(5).trimmingCharacters(in: .whitespaces))
                        }
                    }
                } catch {
                    if Task.isCancelled { break }
                    onConnectionChanged(false)
                    try? await Task.sleep(nanoseconds: backoffSeconds * 1_000_000_000)
                    backoffSeconds = min(backoffSeconds * 2, 30)
                }
            }
            session.invalidateAndCancel()
        }
    }

    func stop() {
        task?.cancel()
        task = nil
    }

    private static func decodeEvent(name: String, payload: String) -> SSEEvent? {
        guard let data = payload.data(using: .utf8) else { return nil }
        let decoder = JSONDecoder()
        switch name {
        case "health":
            if let h = try? decoder.decode(HealthResponse.self, from: data) {
                return .health(h)
            }
        case "email_processed":
            return .emailProcessed
        case "pair_request":
            if let req = try? decoder.decode(IncomingPairRequest.self, from: data) {
                return .pairRequest(req)
            }
        case "scan_progress":
            if let job = try? decoder.decode(ScanJob.self, from: data) {
                return .scanProgress(job)
            }
        case "abuse_queue":
            if let evt = try? decoder.decode(AbuseQueueEvent.self, from: data) {
                return .abuseQueue(evt.pendingCount)
            }
        default:
            break
        }
        return nil
    }
}
