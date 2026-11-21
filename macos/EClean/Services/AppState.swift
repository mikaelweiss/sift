import Foundation
import Observation

@MainActor
@Observable
final class AppState {
    var connection: ServerConnection?
    var health: HealthResponse?
    var stats: [DailyCategoryStat] = []
    var selectedStatsDays: Int = 30
    var totalBlocked: Int = 0
    var settings: AppSettings = AppSettings()
    var categories: [Category] = []
    var allowlist: [AllowlistEntry] = []
    var devices: [PairedDevice] = []
    var latestScan: ScanJob?
    var abuseQueue: [AbuseQueueItem] = []
    var incomingPairRequest: IncomingPairRequest?

    var isConnected: Bool = false
    var isUpdatingServer: Bool = false
    var updateProgressMessage: String = ""
    var errorMessage: String?
    var showSettings: Bool = false

    private let sseClient = SSEClient()

    var apiClient: APIClient? {
        guard let connection else { return nil }
        return APIClient(connection: connection)
    }

    var bundledServerVersion: String {
        (Bundle.main.object(forInfoDictionaryKey: "ECleanBundledServerVersion") as? String) ?? "0.1.0"
    }

    var serverUpdateAvailable: Bool {
        guard let serverVersion = health?.version, !serverVersion.isEmpty else { return false }
        return serverVersion != bundledServerVersion
    }

    func bootstrap() async {
        if let saved = KeychainStore.load() {
            await connect(to: saved)
        }
    }

    func connect(to conn: ServerConnection) async {
        do {
            try KeychainStore.save(conn)
        } catch {
            errorMessage = error.localizedDescription
        }
        connection = conn
        await refreshAll()
        startSSE()
    }

    func refreshAll() async {
        guard let client = apiClient else { return }
        do {
            async let h = client.health()
            async let st = client.dailyStats(days: selectedStatsDays)
            async let cfg = client.getSettings()
            async let cats = client.listCategories()
            async let al = client.listAllowlist()
            async let devs = client.listDevices()
            async let scan = client.latestScan()
            async let queue = client.listAbuseQueue()

            health = try await h
            let statsResp = try await st
            stats = statsResp.stats
            totalBlocked = statsResp.totalBlocked
            settings = try await cfg
            categories = try await cats
            allowlist = try await al
            devices = try await devs
            latestScan = try await scan
            abuseQueue = try await queue
            isConnected = true
            errorMessage = nil
        } catch {
            isConnected = false
            errorMessage = error.localizedDescription
        }
    }

    func refreshStats(days: Int) async {
        selectedStatsDays = days
        guard let client = apiClient else { return }
        do {
            let resp = try await client.dailyStats(days: days)
            stats = resp.stats
            totalBlocked = resp.totalBlocked
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    func refreshAbuseQueue() async {
        guard let client = apiClient else { return }
        if let items = try? await client.listAbuseQueue() {
            abuseQueue = items
        }
    }

    func refreshLatestScan() async {
        guard let client = apiClient else { return }
        if let job = try? await client.latestScan() {
            latestScan = job
        }
    }

    func startSSE() {
        guard let connection else { return }
        sseClient.start(
            connection: connection,
            onEvent: { [weak self] event in
                Task { @MainActor [weak self] in
                    guard let self else { return }
                    switch event {
                    case .health(let h):
                        self.health = h
                    case .emailProcessed:
                        await self.refreshStats(days: self.selectedStatsDays)
                    case .pairRequest(let req):
                        self.incomingPairRequest = req
                    case .scanProgress(let job):
                        self.latestScan = job
                        if job.status == "completed" {
                            await self.refreshStats(days: self.selectedStatsDays)
                        }
                    case .abuseQueue:
                        await self.refreshAbuseQueue()
                    }
                }
            },
            onConnectionChanged: { [weak self] connected in
                Task { @MainActor [weak self] in
                    self?.isConnected = connected
                }
            }
        )
    }

    func stopSSE() {
        sseClient.stop()
    }

    func approveIncomingPair(approve: Bool) async {
        guard let req = incomingPairRequest, let client = apiClient else { return }
        do {
            try await client.approvePair(requestID: req.requestID, approve: approve)
            incomingPairRequest = nil
            devices = try await client.listDevices()
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    func updateServerBinary() async {
        guard let conn = connection else { return }
        isUpdatingServer = true
        updateProgressMessage = "Preparing update..."
        defer {
            isUpdatingServer = false
            updateProgressMessage = ""
        }
        do {
            let target = DeployTarget(
                isLocal: conn.isLocal,
                host: conn.host,
                sshUser: conn.sshUser,
                sshKeyPath: conn.sshKeyPath,
                port: conn.port
            )
            _ = try await SSHDeployer.deployOrUpdate(target: target, isUpdate: true) { msg in
                Task { @MainActor in
                    self.updateProgressMessage = msg
                }
            }
            await refreshAll()
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    func signOut() async {
        if let conn = connection, let client = apiClient {
            try? await client.revokeDevice(id: conn.deviceID)
        }
        stopSSE()
        KeychainStore.clear()
        connection = nil
        health = nil
        stats = []
        abuseQueue = []
        isConnected = false
    }
}
