# EClean Server HTTPS and SSE API Contract

Base URL: `https://<host>:<port>` (default port `8443`, self-signed TLS cert pinned by SHA-256 hex fingerprint).

All `/api/*` endpoints require `Authorization: Bearer <device_token>` except:
- `GET /api/health`
- `POST /api/pair/request`
- `GET /api/pair/status/{request_id}`
- `POST /api/pair/redeem`

## Endpoints

### Health
- `GET /api/health` -> `200 OK`
  ```json
  {
    "version": "0.1.0",
    "os": "linux",
    "arch": "amd64",
    "imap_connected": true,
    "imap_error": "",
    "paired_devices": 1,
    "pending_abuse_count": 2,
    "tls_fingerprint": "<sha256-hex>"
  }
  ```

### Pairing
- `POST /api/pair/request` (body: `{"device_name": "Mikael's MacBook Pro"}`) -> `201 Created`
  ```json
  {
    "request_id": "<uuid>",
    "verification_code": "482910",
    "expires_at": "2026-11-20T16:35:00Z"
  }
  ```
  Broadcasts SSE event `pair_request` to all paired clients.
- `GET /api/pair/status/{request_id}` -> `200 OK`
  ```json
  {
    "status": "pending|approved|denied|expired",
    "device_id": "<uuid>",
    "token": "<raw-token-once-when-approved>"
  }
  ```
- `POST /api/pair/approve` (authenticated, body: `{"request_id": "<uuid>", "approve": true}`) -> `200 OK`
  `{"status": "approved|denied"}`
- `POST /api/pair/redeem` (body: `{"code": "123456", "device_name": "Mac Studio"}`) -> `200 OK`
  ```json
  {
    "device_id": "<uuid>",
    "token": "<raw-device-token>"
  }
  ```
- `GET /api/devices` -> `{"devices": [{"id", "name", "created_at", "last_seen_at"}]}`
- `DELETE /api/devices/{id}` -> `204 No Content`

### Stats
- `GET /api/stats/daily?days=30` (`days=0` means all) -> `200 OK`
  ```json
  {
    "days": 30,
    "total_blocked": 42,
    "stats": [
      {"day": "2026-11-20", "category_id": "phishing_scams", "category_name": "Phishing & Scams", "count": 5}
    ]
  }
  ```

### Settings and Validation
- `GET /api/settings` -> `AppSettings` JSON (secret fields omitted, booleans `has_imap_password`, `has_ai_api_key`, `has_abuse_smtp_password` included).
- `PUT /api/settings` -> accepts partial or full `AppSettings` JSON, persists encrypted secrets if non-empty, reloads IMAP watcher if IMAP/AI/category settings changed.
- `POST /api/validate/imap` (body: `{"host", "port", "username", "password"}`) -> `{"ok": true, "error": ""}`
- `POST /api/validate/ai` (body: `{"provider", "api_key", "model"}`) -> `{"ok": true, "error": ""}`

### Categories
- `GET /api/categories` -> `{"categories": [Category]}`
- `POST /api/categories` (body: `{"name", "description", "enabled", "abuse_eligible"}`) -> `201 Created` (`Category`)
- `PUT /api/categories/{id}` (body: `{"name", "description", "enabled", "abuse_eligible"}`) -> `200 OK` (`Category`)
- `DELETE /api/categories/{id}` -> `204 No Content` (custom categories only)

### Allowlist
- `GET /api/allowlist` -> `{"entries": [AllowlistEntry]}`
- `POST /api/allowlist` (body: `{"pattern": "example.com", "kind": "domain"}`) -> `201 Created` (`AllowlistEntry`)
- `DELETE /api/allowlist/{id}` -> `204 No Content`

### Historical Scans
- `GET /api/scans/latest` -> `{"job": ScanJob | null}`
- `POST /api/scans` (body: `{"date_range": "30d|1y|all", "dry_run": true, "rate_per_sec": 5}`) -> `201 Created` (`{"job": ScanJob}`)
- `POST /api/scans/{id}/pause` -> `{"job": ScanJob}`
- `POST /api/scans/{id}/resume` -> `{"job": ScanJob}`
- `POST /api/scans/{id}/cancel` -> `{"job": ScanJob}`
- `POST /api/scans/{id}/apply` -> `{"job": ScanJob}` (applies a completed Dry Run without re-running Jev)
- `GET /api/scans/{id}/matches` -> `{"matches": [ScanMatch]}` (every email the scan marked for trash or delete, highest confidence first)

### Trash
- `GET /api/trash` -> `{"mailbox", "uid_validity", "items": [TrashItem]}` (only messages EClean moved to Trash, matched by Message-ID)
- `POST /api/trash/delete` (body: `{"uid_validity", "uids": [UID]}`) -> `{"deleted": N}` (permanently deletes listed UIDs that EClean trashed, ignores the rest)

### Abuse Reporting
- `GET /api/abuse/queue` -> `{"items": [AbuseQueueItem]}`
- `POST /api/abuse/{id}/approve` -> `{"status": "sent|failed", "error": ""}`
- `POST /api/abuse/{id}/dismiss` -> `204 No Content`
- `POST /api/abuse/test-smtp` (body: `{"to_email": "..."}`) -> `{"ok": true, "error": ""}`

### Live Event Stream (SSE)
- `GET /api/events` (`text/event-stream`, authenticated via `Authorization: Bearer <token>`)
- Events:
  - `event: health` -> Health payload
  - `event: email_processed` -> `EmailEvent`
  - `event: pair_request` -> `{"request_id", "device_name", "verification_code", "expires_at"}`
  - `event: scan_progress` -> `ScanJob`
  - `event: abuse_queue` -> `{"pending_count": 3}`
