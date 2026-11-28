package api

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/mikaelweiss/sift/server/internal/abuse"
	"github.com/mikaelweiss/sift/server/internal/db"
	"github.com/mikaelweiss/sift/server/internal/imap"
	"github.com/mikaelweiss/sift/server/internal/jev"
	"github.com/mikaelweiss/sift/server/internal/unsubscribe"
)

type pairRequest struct {
	ID               string
	DeviceName       string
	VerificationCode string
	Status           string
	DeviceID         string
	IssuedToken      string
	ExpiresAt        time.Time
}

type Server struct {
	store          *db.Store
	watcher        *imap.Watcher
	scanner        *imap.Scanner
	abuseSvc       *abuse.Service
	hub            *Hub
	unsubscriber   *unsubscribe.Client
	version        string
	tlsFingerprint string

	pairMu       sync.Mutex
	pairRequests map[string]*pairRequest
}

func NewServer(store *db.Store, watcher *imap.Watcher, scanner *imap.Scanner, abuseSvc *abuse.Service, hub *Hub, version, tlsFingerprint string) *Server {
	if hub == nil {
		hub = NewHub()
	}
	srv := &Server{
		store:          store,
		watcher:        watcher,
		scanner:        scanner,
		abuseSvc:       abuseSvc,
		hub:            hub,
		unsubscriber:   unsubscribe.New(),
		version:        version,
		tlsFingerprint: tlsFingerprint,
		pairRequests:   make(map[string]*pairRequest),
	}
	hub.OnSubscribe = func() []sseMessage {
		if msg, ok := NewSSEMessage("health", srv.BuildHealthPayload()); ok {
			return []sseMessage{msg}
		}
		return nil
	}
	return srv
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	// Public endpoints
	mux.HandleFunc("GET /api/health", s.handleHealth)
	mux.HandleFunc("POST /api/pair/request", s.handlePairRequest)
	mux.HandleFunc("GET /api/pair/status/{request_id}", s.handlePairStatus)
	mux.HandleFunc("POST /api/pair/redeem", s.handlePairRedeem)

	// Authenticated endpoints
	mux.Handle("POST /api/pair/approve", s.requireAuth(http.HandlerFunc(s.handlePairApprove)))
	mux.Handle("GET /api/devices", s.requireAuth(http.HandlerFunc(s.handleListDevices)))
	mux.Handle("DELETE /api/devices/{id}", s.requireAuth(http.HandlerFunc(s.handleDeleteDevice)))

	mux.Handle("GET /api/stats/daily", s.requireAuth(http.HandlerFunc(s.handleDailyStats)))

	mux.Handle("GET /api/settings", s.requireAuth(http.HandlerFunc(s.handleGetSettings)))
	mux.Handle("PUT /api/settings", s.requireAuth(http.HandlerFunc(s.handlePutSettings)))
	mux.Handle("POST /api/validate/imap", s.requireAuth(http.HandlerFunc(s.handleValidateIMAP)))
	mux.Handle("POST /api/validate/ai", s.requireAuth(http.HandlerFunc(s.handleValidateAI)))

	mux.Handle("GET /api/categories", s.requireAuth(http.HandlerFunc(s.handleListCategories)))
	mux.Handle("POST /api/categories", s.requireAuth(http.HandlerFunc(s.handleCreateCategory)))
	mux.Handle("PUT /api/categories/{id}", s.requireAuth(http.HandlerFunc(s.handleUpdateCategory)))
	mux.Handle("DELETE /api/categories/{id}", s.requireAuth(http.HandlerFunc(s.handleDeleteCategory)))

	mux.Handle("GET /api/allowlist", s.requireAuth(http.HandlerFunc(s.handleListAllowlist)))
	mux.Handle("POST /api/allowlist", s.requireAuth(http.HandlerFunc(s.handleAddAllowlist)))
	mux.Handle("DELETE /api/allowlist/{id}", s.requireAuth(http.HandlerFunc(s.handleDeleteAllowlist)))

	mux.Handle("GET /api/scans/latest", s.requireAuth(http.HandlerFunc(s.handleLatestScan)))
	mux.Handle("POST /api/scans", s.requireAuth(http.HandlerFunc(s.handleStartScan)))
	mux.Handle("POST /api/scans/{id}/pause", s.requireAuth(http.HandlerFunc(s.handlePauseScan)))
	mux.Handle("POST /api/scans/{id}/resume", s.requireAuth(http.HandlerFunc(s.handleResumeScan)))
	mux.Handle("POST /api/scans/{id}/cancel", s.requireAuth(http.HandlerFunc(s.handleCancelScan)))
	mux.Handle("POST /api/scans/{id}/apply", s.requireAuth(http.HandlerFunc(s.handleApplyScan)))
	mux.Handle("GET /api/scans/{id}/matches", s.requireAuth(http.HandlerFunc(s.handleScanMatches)))

	mux.Handle("GET /api/junk", s.requireAuth(http.HandlerFunc(s.handleListJunk)))
	mux.Handle("POST /api/junk/delete", s.requireAuth(http.HandlerFunc(s.handleDeleteJunk)))

	mux.Handle("GET /api/mailing-lists", s.requireAuth(http.HandlerFunc(s.handleListMailingLists)))
	mux.Handle("POST /api/mailing-lists/unsubscribe", s.requireAuth(http.HandlerFunc(s.handleUnsubscribe)))

	mux.Handle("GET /api/abuse/queue", s.requireAuth(http.HandlerFunc(s.handleListAbuseQueue)))
	mux.Handle("POST /api/abuse/{id}/approve", s.requireAuth(http.HandlerFunc(s.handleApproveAbuse)))
	mux.Handle("POST /api/abuse/{id}/dismiss", s.requireAuth(http.HandlerFunc(s.handleDismissAbuse)))
	mux.Handle("GET /api/abuse/history", s.requireAuth(http.HandlerFunc(s.handleAbuseHistory)))
	mux.Handle("POST /api/abuse/sync", s.requireAuth(http.HandlerFunc(s.handleSyncAbuseReplies)))
	mux.Handle("DELETE /api/abuse/form-only/{domain}", s.requireAuth(http.HandlerFunc(s.handleDeleteFormOnlyDomain)))

	mux.Handle("GET /api/events", s.requireAuth(s.hub))

	return mux
}

func (s *Server) requireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if !strings.HasPrefix(auth, "Bearer ") {
			writeError(w, http.StatusUnauthorized, "missing bearer token")
			return
		}
		token := strings.TrimSpace(strings.TrimPrefix(auth, "Bearer "))
		if token == "" {
			writeError(w, http.StatusUnauthorized, "empty bearer token")
			return
		}
		dev, err := s.store.FindDeviceByTokenHash(hashString(token))
		if err != nil || dev == nil {
			writeError(w, http.StatusUnauthorized, "invalid device token")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) BuildHealthPayload() map[string]any {
	var imapSnap imap.StatusSnapshot
	if s.watcher != nil {
		imapSnap = s.watcher.Status()
	}
	pairedCount, _ := s.store.CountPairedDevices()
	queue, _ := s.store.ListAbuseQueue()
	bannedCount, _ := s.store.CountAbuseBans()
	return map[string]any{
		"version":             s.version,
		"os":                  runtime.GOOS,
		"arch":                runtime.GOARCH,
		"imap_connected":      imapSnap.Connected,
		"imap_error":          imapSnap.LastError,
		"paired_devices":      pairedCount,
		"pending_abuse_count": len(queue),
		"banned_count":        bannedCount,
		"tls_fingerprint":     s.tlsFingerprint,
	}
}

func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, s.BuildHealthPayload())
}

func (s *Server) handlePairRequest(w http.ResponseWriter, r *http.Request) {
	var body struct {
		DeviceName string `json:"device_name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	name := strings.TrimSpace(body.DeviceName)
	if name == "" {
		name = "Mac"
	}
	code, err := randomSixDigits()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	req := &pairRequest{
		ID:               uuid.NewString(),
		DeviceName:       name,
		VerificationCode: code,
		Status:           "pending",
		ExpiresAt:        time.Now().UTC().Add(5 * time.Minute),
	}

	s.pairMu.Lock()
	s.pairRequests[req.ID] = req
	s.pairMu.Unlock()

	s.hub.Publish("pair_request", map[string]any{
		"request_id":        req.ID,
		"device_name":       req.DeviceName,
		"verification_code": req.VerificationCode,
		"expires_at":        req.ExpiresAt.Format(time.RFC3339),
	})

	writeJSON(w, http.StatusCreated, map[string]any{
		"request_id":        req.ID,
		"verification_code": req.VerificationCode,
		"expires_at":        req.ExpiresAt.Format(time.RFC3339),
	})
}

func (s *Server) handlePairStatus(w http.ResponseWriter, r *http.Request) {
	reqID := r.PathValue("request_id")
	s.pairMu.Lock()
	defer s.pairMu.Unlock()

	req, ok := s.pairRequests[reqID]
	if !ok {
		writeError(w, http.StatusNotFound, "pair request not found")
		return
	}
	if req.Status == "pending" && time.Now().UTC().After(req.ExpiresAt) {
		req.Status = "expired"
	}

	resp := map[string]any{
		"status":    req.Status,
		"device_id": req.DeviceID,
	}
	if req.Status == "approved" && req.IssuedToken != "" {
		resp["token"] = req.IssuedToken
		req.IssuedToken = ""
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handlePairApprove(w http.ResponseWriter, r *http.Request) {
	var body struct {
		RequestID string `json:"request_id"`
		Approve   bool   `json:"approve"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}

	s.pairMu.Lock()
	defer s.pairMu.Unlock()

	req, ok := s.pairRequests[body.RequestID]
	if !ok {
		writeError(w, http.StatusNotFound, "pair request not found")
		return
	}
	if time.Now().UTC().After(req.ExpiresAt) {
		req.Status = "expired"
		writeError(w, http.StatusGone, "pair request expired")
		return
	}
	if !body.Approve {
		req.Status = "denied"
		writeJSON(w, http.StatusOK, map[string]string{"status": "denied"})
		return
	}

	deviceID, rawToken, err := s.issuePairedDevice(req.DeviceName)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	req.Status = "approved"
	req.DeviceID = deviceID
	req.IssuedToken = rawToken
	writeJSON(w, http.StatusOK, map[string]string{"status": "approved"})
}

func (s *Server) handlePairRedeem(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Code       string `json:"code"`
		DeviceName string `json:"device_name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	code := strings.TrimSpace(body.Code)
	if code == "" {
		writeError(w, http.StatusBadRequest, "pairing code is required")
		return
	}
	ok, err := s.store.ConsumePairingCode(hashString(code))
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !ok {
		writeError(w, http.StatusUnauthorized, "invalid or expired pairing code")
		return
	}
	name := strings.TrimSpace(body.DeviceName)
	if name == "" {
		name = "Mac"
	}
	deviceID, rawToken, err := s.issuePairedDevice(name)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{
		"device_id": deviceID,
		"token":     rawToken,
	})
}

func (s *Server) issuePairedDevice(name string) (deviceID, rawToken string, err error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", "", err
	}
	rawToken = hex.EncodeToString(buf)
	deviceID = uuid.NewString()
	_, err = s.store.CreatePairedDevice(deviceID, name, hashString(rawToken))
	return deviceID, rawToken, err
}

func (s *Server) handleListDevices(w http.ResponseWriter, _ *http.Request) {
	devices, err := s.store.ListPairedDevices()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if devices == nil {
		devices = []db.PairedDevice{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"devices": devices})
}

func (s *Server) handleDeleteDevice(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := s.store.DeletePairedDevice(id); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleDailyStats(w http.ResponseWriter, r *http.Request) {
	days := 30
	if raw := r.URL.Query().Get("days"); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil && n >= 0 {
			days = n
		}
	}
	stats, err := s.store.DailySpamStats(days)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if stats == nil {
		stats = []db.DailyCategoryStat{}
	}
	total := 0
	for _, st := range stats {
		total += st.Count
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"days":          days,
		"total_blocked": total,
		"stats":         stats,
	})
}

type settingsResponse struct {
	db.AppSettings
	HasIMAPPassword bool `json:"has_imap_password"`
	HasAIAPIKey     bool `json:"has_ai_api_key"`
}

func (s *Server) handleGetSettings(w http.ResponseWriter, _ *http.Request) {
	cfg, err := s.store.GetSettings()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	resp := settingsResponse{
		AppSettings:     cfg,
		HasIMAPPassword: cfg.IMAPPassword != "",
		HasAIAPIKey:     cfg.AIAPIKey != "",
	}
	resp.IMAPPassword = ""
	resp.AIAPIKey = ""
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handlePutSettings(w http.ResponseWriter, r *http.Request) {
	current, err := s.store.GetSettings()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	incoming := current
	incoming.IMAPPassword = ""
	incoming.AIAPIKey = ""
	if err := json.NewDecoder(r.Body).Decode(&incoming); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	if err := s.store.SaveSettings(incoming); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if s.watcher != nil {
		s.watcher.TriggerReload()
	}
	s.handleGetSettings(w, r)
}

func (s *Server) handleValidateIMAP(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Host     string `json:"host"`
		Port     int    `json:"port"`
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	if body.Password == "" {
		if cfg, err := s.store.GetSettings(); err == nil {
			body.Password = cfg.IMAPPassword
		}
	}
	if err := imap.TestConnection(body.Host, body.Port, body.Username, body.Password); err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "error": ""})
}

func (s *Server) handleValidateAI(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Provider string `json:"provider"`
		APIKey   string `json:"api_key"`
		Model    string `json:"model"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	if body.APIKey == "" {
		if cfg, err := s.store.GetSettings(); err == nil {
			body.APIKey = cfg.AIAPIKey
		}
	}
	client := jev.NewClient(body.Provider, body.APIKey, body.Model)
	if err := client.VerifyKey(r.Context()); err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "error": ""})
}

func (s *Server) handleListCategories(w http.ResponseWriter, _ *http.Request) {
	cats, err := s.store.ListCategories()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if cats == nil {
		cats = []db.Category{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"categories": cats})
}

func (s *Server) handleCreateCategory(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Name          string `json:"name"`
		Description   string `json:"description"`
		Enabled       bool   `json:"enabled"`
		AbuseEligible bool   `json:"abuse_eligible"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	name := strings.TrimSpace(body.Name)
	if name == "" {
		writeError(w, http.StatusBadRequest, "name is required")
		return
	}
	cat := db.Category{
		ID:            "custom_" + strings.ReplaceAll(uuid.NewString()[:8], "-", ""),
		Name:          name,
		Description:   strings.TrimSpace(body.Description),
		Enabled:       body.Enabled,
		Builtin:       false,
		AbuseEligible: body.AbuseEligible,
		CreatedAt:     time.Now().UTC().Format(time.RFC3339),
	}
	if err := s.store.UpsertCategory(cat); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, cat)
}

func (s *Server) handleUpdateCategory(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var body struct {
		Name          string `json:"name"`
		Description   string `json:"description"`
		Enabled       bool   `json:"enabled"`
		AbuseEligible bool   `json:"abuse_eligible"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	cats, err := s.store.ListCategories()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	var existing *db.Category
	for i := range cats {
		if cats[i].ID == id {
			existing = &cats[i]
			break
		}
	}
	if existing == nil {
		writeError(w, http.StatusNotFound, "category not found")
		return
	}
	if strings.TrimSpace(body.Name) != "" {
		existing.Name = strings.TrimSpace(body.Name)
	}
	if strings.TrimSpace(body.Description) != "" {
		existing.Description = strings.TrimSpace(body.Description)
	}
	existing.Enabled = body.Enabled
	existing.AbuseEligible = body.AbuseEligible
	if err := s.store.UpsertCategory(*existing); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, existing)
}

func (s *Server) handleDeleteCategory(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := s.store.DeleteCategory(id); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleListAllowlist(w http.ResponseWriter, _ *http.Request) {
	entries, err := s.store.ListAllowlist()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if entries == nil {
		entries = []db.AllowlistEntry{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"entries": entries})
}

func (s *Server) handleAddAllowlist(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Pattern string `json:"pattern"`
		Kind    string `json:"kind"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	entry, err := s.store.AddAllowlistEntry(body.Pattern, body.Kind)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, entry)
}

func (s *Server) handleDeleteAllowlist(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid id")
		return
	}
	if err := s.store.DeleteAllowlistEntry(id); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleLatestScan(w http.ResponseWriter, _ *http.Request) {
	job, err := s.store.GetLatestScanJob()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"job": job})
}

func (s *Server) handleStartScan(w http.ResponseWriter, r *http.Request) {
	if s.scanner == nil {
		writeError(w, http.StatusServiceUnavailable, "scanner unavailable")
		return
	}
	var body struct {
		DateRange  string  `json:"date_range"`
		DryRun     bool    `json:"dry_run"`
		RatePerSec float64 `json:"rate_per_sec"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	job, err := s.scanner.Start(body.DateRange, body.DryRun, body.RatePerSec)
	if err != nil {
		writeError(w, http.StatusConflict, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"job": job})
}

func (s *Server) handlePauseScan(w http.ResponseWriter, r *http.Request) {
	if s.scanner == nil {
		writeError(w, http.StatusServiceUnavailable, "scanner unavailable")
		return
	}
	job, err := s.scanner.Pause(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"job": job})
}

func (s *Server) handleResumeScan(w http.ResponseWriter, r *http.Request) {
	if s.scanner == nil {
		writeError(w, http.StatusServiceUnavailable, "scanner unavailable")
		return
	}
	job, err := s.scanner.Resume(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"job": job})
}

func (s *Server) handleCancelScan(w http.ResponseWriter, r *http.Request) {
	if s.scanner == nil {
		writeError(w, http.StatusServiceUnavailable, "scanner unavailable")
		return
	}
	job, err := s.scanner.Cancel(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"job": job})
}

func (s *Server) handleApplyScan(w http.ResponseWriter, r *http.Request) {
	if s.scanner == nil {
		writeError(w, http.StatusServiceUnavailable, "scanner unavailable")
		return
	}
	job, err := s.scanner.Apply(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"job": job})
}

func (s *Server) handleScanMatches(w http.ResponseWriter, r *http.Request) {
	matches, err := s.store.ListScanMatches(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"matches": matches})
}

func (s *Server) handleListJunk(w http.ResponseWriter, _ *http.Request) {
	listing, err := imap.ListJunk(s.store)
	if err != nil {
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, listing)
}

func (s *Server) handleDeleteJunk(w http.ResponseWriter, r *http.Request) {
	var body struct {
		UIDValidity uint32   `json:"uid_validity"`
		UIDs        []uint32 `json:"uids"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	deleted, err := imap.DeleteFromJunk(s.store, body.UIDValidity, body.UIDs)
	if err != nil {
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"deleted": deleted})
}

func (s *Server) handleListMailingLists(w http.ResponseWriter, _ *http.Request) {
	lists, err := s.store.ListLegitMailingLists()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"lists": lists})
}

func (s *Server) handleUnsubscribe(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Sender string `json:"sender"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	list, err := s.store.GetLegitMailingList(body.Sender)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if list == nil {
		writeError(w, http.StatusNotFound, "this sender is not an eligible mailing list")
		return
	}
	unsubscribedAt, errMsg := "", ""
	if err := s.unsubscriber.OneClick(r.Context(), list.UnsubscribeURL); err != nil {
		errMsg = err.Error()
	} else {
		unsubscribedAt = time.Now().UTC().Format(time.RFC3339)
	}
	if err := s.store.MarkMailingListResult(list.Sender, unsubscribedAt, errMsg); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	list.UnsubscribedAt, list.Error = unsubscribedAt, errMsg
	writeJSON(w, http.StatusOK, list)
}

func (s *Server) handleAbuseHistory(w http.ResponseWriter, _ *http.Request) {
	entries, err := s.store.ListAbuseHistory(50)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	bannedCount, _ := s.store.CountAbuseBans()
	bans, _ := s.store.ListAbuseBans(50)
	if bans == nil {
		bans = []db.AbuseReply{}
	}
	formOnly, _ := s.store.ListFormOnlyAbuseDomains()
	if formOnly == nil {
		formOnly = []string{}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"entries":           entries,
		"banned_count":      bannedCount,
		"bans":              bans,
		"form_only_domains": formOnly,
	})
}

func (s *Server) handleSyncAbuseReplies(w http.ResponseWriter, r *http.Request) {
	if s.abuseSvc == nil {
		writeError(w, http.StatusServiceUnavailable, "abuse service unavailable")
		return
	}
	res, err := imap.SyncAbuseReplies(r.Context(), s.store, s.abuseSvc, 90)
	if err != nil {
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	s.hub.Publish("health", s.BuildHealthPayload())
	writeJSON(w, http.StatusOK, res)
}

func (s *Server) handleDeleteFormOnlyDomain(w http.ResponseWriter, r *http.Request) {
	domain := strings.TrimSpace(r.PathValue("domain"))
	if domain == "" {
		writeError(w, http.StatusBadRequest, "domain is required")
		return
	}
	if err := s.store.DeleteFormOnlyAbuseDomain(domain); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleListAbuseQueue(w http.ResponseWriter, _ *http.Request) {
	items, err := s.store.ListAbuseQueue()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if items == nil {
		items = []db.AbuseQueueItem{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (s *Server) handleApproveAbuse(w http.ResponseWriter, r *http.Request) {
	if s.abuseSvc == nil {
		writeError(w, http.StatusServiceUnavailable, "abuse service unavailable")
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid id")
		return
	}
	if err := s.abuseSvc.Approve(id); err != nil {
		writeError(w, http.StatusConflict, err.Error())
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]any{"status": "sending"})
}

func (s *Server) handleDismissAbuse(w http.ResponseWriter, r *http.Request) {
	if s.abuseSvc == nil {
		writeError(w, http.StatusServiceUnavailable, "abuse service unavailable")
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid id")
		return
	}
	if err := s.abuseSvc.Dismiss(id); err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func hashString(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func randomSixDigits() (string, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(1000000))
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%06d", n.Int64()), nil
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	if msg == "" {
		msg = errors.New("request failed").Error()
	}
	writeJSON(w, status, map[string]string{"error": msg})
}
