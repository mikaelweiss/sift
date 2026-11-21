package db

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/mikaelweiss/eclean/server/internal/config"
	_ "modernc.org/sqlite"
)

type Store struct {
	db  *sql.DB
	box *config.SecretBox
}

type Category struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	Description   string `json:"description"`
	Enabled       bool   `json:"enabled"`
	Builtin       bool   `json:"builtin"`
	AbuseEligible bool   `json:"abuse_eligible"`
	CreatedAt     string `json:"created_at"`
}

type AllowlistEntry struct {
	ID        int64  `json:"id"`
	Pattern   string `json:"pattern"`
	Kind      string `json:"kind"`
	CreatedAt string `json:"created_at"`
}

type AppSettings struct {
	IMAPHost            string  `json:"imap_host"`
	IMAPPort            int     `json:"imap_port"`
	IMAPUsername        string  `json:"imap_username"`
	IMAPPassword        string  `json:"imap_password,omitempty"`
	AIProvider          string  `json:"ai_provider"`
	AIAPIKey            string  `json:"ai_api_key,omitempty"`
	AIModel             string  `json:"ai_model"`
	SpamAction          string  `json:"spam_action"`
	TrashThreshold      float64 `json:"trash_threshold"`
	DeleteThreshold     float64 `json:"delete_threshold"`
	AbuseEnabled        bool    `json:"abuse_enabled"`
	AbuseManualApproval bool    `json:"abuse_manual_approval"`
	AbuseMinConfidence  float64 `json:"abuse_min_confidence"`
	AbuseCooldownDays   int     `json:"abuse_cooldown_days"`
	AbuseSMTPMode       string  `json:"abuse_smtp_mode"`
	AbuseFromEmail      string  `json:"abuse_from_email"`
	AbuseSMTPHost       string  `json:"abuse_smtp_host"`
	AbuseSMTPPort       int     `json:"abuse_smtp_port"`
	AbuseSMTPUsername   string  `json:"abuse_smtp_username"`
	AbuseSMTPPassword   string  `json:"abuse_smtp_password,omitempty"`
}

type EmailEvent struct {
	ID           int64   `json:"id"`
	Mailbox      string  `json:"mailbox"`
	UIDValidity  uint32  `json:"uid_validity"`
	UID          uint32  `json:"uid"`
	MessageID    string  `json:"message_id"`
	Sender       string  `json:"sender"`
	SenderDomain string  `json:"sender_domain"`
	Subject      string  `json:"subject"`
	EmailDate    string  `json:"email_date"`
	ProcessedAt  string  `json:"processed_at"`
	CategoryID   string  `json:"category_id"`
	Confidence   float64 `json:"confidence"`
	Action       string  `json:"action"`
	Source       string  `json:"source"`
}

type DailyCategoryStat struct {
	Day          string `json:"day"`
	CategoryID   string `json:"category_id"`
	CategoryName string `json:"category_name"`
	Count        int    `json:"count"`
}

type ScanJob struct {
	ID              string            `json:"id"`
	DateRange       string            `json:"date_range"`
	DryRun          bool              `json:"dry_run"`
	RatePerSec      float64           `json:"rate_per_sec"`
	Status          string            `json:"status"`
	CurrentMailbox  string            `json:"current_mailbox"`
	TotalMessages   int               `json:"total_messages"`
	ScannedMessages int               `json:"scanned_messages"`
	SpamFound       int               `json:"spam_found"`
	LastUID         uint32            `json:"last_uid"`
	Checkpoints     map[string]uint32 `json:"checkpoints"`
	Summary         map[string]int    `json:"summary"`
	Samples         []ScanSample      `json:"samples"`
	ErrorMsg        string            `json:"error_msg"`
	CreatedAt       string            `json:"created_at"`
	UpdatedAt       string            `json:"updated_at"`
}

type ScanSample struct {
	Mailbox    string  `json:"mailbox"`
	UID        uint32  `json:"uid"`
	Sender     string  `json:"sender"`
	Subject    string  `json:"subject"`
	EmailDate  string  `json:"email_date"`
	CategoryID string  `json:"category_id"`
	Confidence float64 `json:"confidence"`
	Action     string  `json:"action"`
}

type AbuseQueueItem struct {
	ID                 int64    `json:"id"`
	RootDomain         string   `json:"root_domain"`
	SendingIP          string   `json:"sending_ip"`
	CategoryID         string   `json:"category_id"`
	Confidence         float64  `json:"confidence"`
	HitCount           int      `json:"hit_count"`
	Targets            []string `json:"targets"`
	RedactedHeaders    string   `json:"redacted_headers"`
	Subject            string   `json:"subject"`
	Sender             string   `json:"sender"`
	RepeatOffense      bool     `json:"repeat_offense"`
	PreviousReportedAt string   `json:"previous_reported_at,omitempty"`
	CreatedAt          string   `json:"created_at"`
	UpdatedAt          string   `json:"updated_at"`
}

type AbuseHistoryEntry struct {
	ID         int64    `json:"id"`
	RootDomain string   `json:"root_domain"`
	SendingIP  string   `json:"sending_ip"`
	CategoryID string   `json:"category_id"`
	HitCount   int      `json:"hit_count"`
	Targets    []string `json:"targets"`
	Status     string   `json:"status"`
	ErrorMsg   string   `json:"error_msg,omitempty"`
	ReportedAt string   `json:"reported_at"`
}

type PairedDevice struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	CreatedAt  string `json:"created_at"`
	LastSeenAt string `json:"last_seen_at"`
}

func Open(dataDir string) (*Store, error) {
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return nil, fmt.Errorf("create data dir: %w", err)
	}
	box, err := config.LoadOrCreateSecretBox(dataDir)
	if err != nil {
		return nil, err
	}
	dbPath := filepath.Join(dataDir, "eclean.db")
	conn, err := sql.Open("sqlite", dbPath+"?_pragma=journal_mode(WAL)&_pragma=foreign_keys(ON)&_pragma=busy_timeout(5000)")
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
	conn.SetMaxOpenConns(1)

	s := &Store{db: conn, box: box}
	if err := s.migrate(); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("migrate sqlite: %w", err)
	}
	return s, nil
}

func (s *Store) Close() error {
	return s.db.Close()
}

func (s *Store) migrate() error {
	if _, err := s.db.Exec(`CREATE TABLE IF NOT EXISTS schema_migrations (
		version INTEGER PRIMARY KEY,
		applied_at TEXT NOT NULL
	)`); err != nil {
		return err
	}

	migrations := []struct {
		version int
		stmts   []string
	}{
		{
			version: 1,
			stmts: []string{
				`CREATE TABLE IF NOT EXISTS settings (
					key TEXT PRIMARY KEY,
					value TEXT NOT NULL,
					encrypted INTEGER NOT NULL DEFAULT 0,
					updated_at TEXT NOT NULL
				)`,
				`CREATE TABLE IF NOT EXISTS categories (
					id TEXT PRIMARY KEY,
					name TEXT NOT NULL,
					description TEXT NOT NULL,
					enabled INTEGER NOT NULL DEFAULT 1,
					builtin INTEGER NOT NULL DEFAULT 0,
					abuse_eligible INTEGER NOT NULL DEFAULT 0,
					created_at TEXT NOT NULL
				)`,
				`CREATE TABLE IF NOT EXISTS allowlist (
					id INTEGER PRIMARY KEY AUTOINCREMENT,
					pattern TEXT NOT NULL UNIQUE,
					kind TEXT NOT NULL,
					created_at TEXT NOT NULL
				)`,
				`CREATE TABLE IF NOT EXISTS email_events (
					id INTEGER PRIMARY KEY AUTOINCREMENT,
					uid_validity INTEGER NOT NULL,
					uid INTEGER NOT NULL,
					message_id TEXT NOT NULL DEFAULT '',
					sender TEXT NOT NULL,
					sender_domain TEXT NOT NULL,
					subject TEXT NOT NULL,
					email_date TEXT NOT NULL,
					processed_at TEXT NOT NULL,
					category_id TEXT NOT NULL DEFAULT '',
					confidence REAL NOT NULL DEFAULT 0,
					action TEXT NOT NULL,
					source TEXT NOT NULL,
					UNIQUE(uid_validity, uid)
				)`,
				`CREATE INDEX IF NOT EXISTS idx_email_events_date_cat ON email_events(email_date, category_id, action)`,
				`CREATE TABLE IF NOT EXISTS scan_jobs (
					id TEXT PRIMARY KEY,
					date_range TEXT NOT NULL,
					dry_run INTEGER NOT NULL,
					rate_per_sec REAL NOT NULL,
					status TEXT NOT NULL,
					total_messages INTEGER NOT NULL DEFAULT 0,
					scanned_messages INTEGER NOT NULL DEFAULT 0,
					spam_found INTEGER NOT NULL DEFAULT 0,
					last_uid INTEGER NOT NULL DEFAULT 0,
					summary_json TEXT NOT NULL DEFAULT '{}',
					samples_json TEXT NOT NULL DEFAULT '[]',
					error_msg TEXT NOT NULL DEFAULT '',
					created_at TEXT NOT NULL,
					updated_at TEXT NOT NULL
				)`,
				`CREATE TABLE IF NOT EXISTS abuse_queue (
					id INTEGER PRIMARY KEY AUTOINCREMENT,
					root_domain TEXT NOT NULL UNIQUE,
					sending_ip TEXT NOT NULL,
					category_id TEXT NOT NULL,
					confidence REAL NOT NULL,
					hit_count INTEGER NOT NULL DEFAULT 1,
					targets_json TEXT NOT NULL DEFAULT '[]',
					redacted_headers TEXT NOT NULL,
					subject TEXT NOT NULL,
					sender TEXT NOT NULL,
					repeat_offense INTEGER NOT NULL DEFAULT 0,
					previous_reported_at TEXT NOT NULL DEFAULT '',
					created_at TEXT NOT NULL,
					updated_at TEXT NOT NULL
				)`,
				`CREATE TABLE IF NOT EXISTS abuse_history (
					id INTEGER PRIMARY KEY AUTOINCREMENT,
					root_domain TEXT NOT NULL,
					sending_ip TEXT NOT NULL,
					category_id TEXT NOT NULL,
					hit_count INTEGER NOT NULL,
					targets_json TEXT NOT NULL,
					status TEXT NOT NULL,
					error_msg TEXT NOT NULL DEFAULT '',
					reported_at TEXT NOT NULL
				)`,
				`CREATE INDEX IF NOT EXISTS idx_abuse_history_domain ON abuse_history(root_domain, reported_at)`,
				`CREATE TABLE IF NOT EXISTS abuse_dismissed (
					root_domain TEXT PRIMARY KEY,
					dismissed_at TEXT NOT NULL
				)`,
				`CREATE TABLE IF NOT EXISTS rdap_cache (
					lookup_key TEXT PRIMARY KEY,
					contacts_json TEXT NOT NULL,
					expires_at TEXT NOT NULL
				)`,
				`CREATE TABLE IF NOT EXISTS paired_devices (
					id TEXT PRIMARY KEY,
					name TEXT NOT NULL,
					token_hash TEXT NOT NULL UNIQUE,
					created_at TEXT NOT NULL,
					last_seen_at TEXT NOT NULL
				)`,
				`CREATE TABLE IF NOT EXISTS pairing_codes (
					code_hash TEXT PRIMARY KEY,
					expires_at TEXT NOT NULL,
					used INTEGER NOT NULL DEFAULT 0
				)`,
			},
		},
		{
			version: 2,
			stmts: []string{
				`UPDATE settings SET value = 'true' WHERE key = 'abuse_enabled' AND value = 'false'`,
			},
		},
		{
			version: 3,
			stmts: []string{
				`CREATE TABLE IF NOT EXISTS imap_cursors (
					mailbox TEXT PRIMARY KEY,
					uid_validity INTEGER NOT NULL,
					last_uid INTEGER NOT NULL
				)`,
				`CREATE TABLE email_events_v3 (
					id INTEGER PRIMARY KEY AUTOINCREMENT,
					mailbox TEXT NOT NULL DEFAULT 'INBOX',
					uid_validity INTEGER NOT NULL,
					uid INTEGER NOT NULL,
					message_id TEXT NOT NULL DEFAULT '',
					sender TEXT NOT NULL,
					sender_domain TEXT NOT NULL,
					subject TEXT NOT NULL,
					email_date TEXT NOT NULL,
					processed_at TEXT NOT NULL,
					category_id TEXT NOT NULL DEFAULT '',
					confidence REAL NOT NULL DEFAULT 0,
					action TEXT NOT NULL,
					source TEXT NOT NULL,
					UNIQUE(mailbox, uid_validity, uid)
				)`,
				`INSERT INTO email_events_v3(id, mailbox, uid_validity, uid, message_id, sender, sender_domain, subject, email_date, processed_at, category_id, confidence, action, source)
				 SELECT id, 'INBOX', uid_validity, uid, message_id, sender, sender_domain, subject, email_date, processed_at, category_id, confidence, action, source FROM email_events`,
				`DROP TABLE email_events`,
				`ALTER TABLE email_events_v3 RENAME TO email_events`,
				`CREATE INDEX IF NOT EXISTS idx_email_events_date_cat ON email_events(email_date, category_id, action)`,
				`ALTER TABLE scan_jobs ADD COLUMN current_mailbox TEXT NOT NULL DEFAULT ''`,
				`ALTER TABLE scan_jobs ADD COLUMN checkpoints_json TEXT NOT NULL DEFAULT '{}'`,
			},
		},
	}

	now := time.Now().UTC().Format(time.RFC3339)
	for _, m := range migrations {
		var exists int
		if err := s.db.QueryRow(`SELECT COUNT(1) FROM schema_migrations WHERE version = ?`, m.version).Scan(&exists); err != nil {
			return err
		}
		if exists > 0 {
			continue
		}
		tx, err := s.db.Begin()
		if err != nil {
			return err
		}
		for _, stmt := range m.stmts {
			if _, err := tx.Exec(stmt); err != nil {
				_ = tx.Rollback()
				return fmt.Errorf("migration %d failed: %w", m.version, err)
			}
		}
		if _, err := tx.Exec(`INSERT INTO schema_migrations(version, applied_at) VALUES(?, ?)`, m.version, now); err != nil {
			_ = tx.Rollback()
			return err
		}
		if err := tx.Commit(); err != nil {
			return err
		}
	}

	return s.seedBuiltinCategories()
}

func (s *Store) seedBuiltinCategories() error {
	now := time.Now().UTC().Format(time.RFC3339)
	defaults := []Category{
		{
			ID:            "phishing_scams",
			Name:          "Phishing & Scams",
			Description:   "Fraudulent emails impersonating trusted services, requesting credentials, wire transfers, gift cards, fake invoices, or urgent account verification.",
			Enabled:       true,
			Builtin:       true,
			AbuseEligible: true,
		},
		{
			ID:            "marketing_promotions",
			Name:          "Marketing & Promotions",
			Description:   "Commercial promotional blasts, discount offers, product announcements, retail sales, and mass advertising emails.",
			Enabled:       true,
			Builtin:       true,
			AbuseEligible: false,
		},
		{
			ID:            "cold_sales",
			Name:          "Cold Sales & Outreach",
			Description:   "Unsolicited B2B sales pitches, lead generation outreach, recruiter spam, and cold partnership requests from strangers.",
			Enabled:       true,
			Builtin:       true,
			AbuseEligible: false,
		},
		{
			ID:            "newsletters",
			Name:          "Newsletters",
			Description:   "Periodic email digests, blog roundups, Substack or mailing list publications, and editorial updates.",
			Enabled:       false,
			Builtin:       true,
			AbuseEligible: false,
		},
		{
			ID:            "crypto_gambling",
			Name:          "Crypto & Gambling",
			Description:   "Unsolicited cryptocurrency offers, token pumps, forex or trading schemes, online casino promos, and sports betting spam.",
			Enabled:       true,
			Builtin:       true,
			AbuseEligible: true,
		},
		{
			ID:            "adult_explicit",
			Name:          "Adult & Explicit Content",
			Description:   "Unsolicited pornographic websites, sexually explicit offers, adult dating spam, escort ads, and NSFW solicitations.",
			Enabled:       true,
			Builtin:       true,
			AbuseEligible: true,
		},
		{
			ID:            "political_fundraising",
			Name:          "Political & Fundraising",
			Description:   "Political campaign solicitations, PAC donation drives, petition blasts, and mass fundraising appeals.",
			Enabled:       false,
			Builtin:       true,
			AbuseEligible: false,
		},
	}

	for _, c := range defaults {
		if _, err := s.db.Exec(
			`INSERT OR IGNORE INTO categories(id, name, description, enabled, builtin, abuse_eligible, created_at) VALUES(?, ?, ?, ?, ?, ?, ?)`,
			c.ID, c.Name, c.Description, boolToInt(c.Enabled), boolToInt(c.Builtin), boolToInt(c.AbuseEligible), now,
		); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) SetRawSetting(key, value string, encrypted bool) error {
	stored := value
	if encrypted && value != "" {
		enc, err := s.box.Encrypt(value)
		if err != nil {
			return fmt.Errorf("encrypt setting %s: %w", key, err)
		}
		stored = enc
	}
	now := time.Now().UTC().Format(time.RFC3339)
	_, err := s.db.Exec(
		`INSERT INTO settings(key, value, encrypted, updated_at) VALUES(?, ?, ?, ?)
		 ON CONFLICT(key) DO UPDATE SET value=excluded.value, encrypted=excluded.encrypted, updated_at=excluded.updated_at`,
		key, stored, boolToInt(encrypted), now,
	)
	return err
}

func (s *Store) GetRawSetting(key string) (string, bool, error) {
	var raw string
	var enc int
	err := s.db.QueryRow(`SELECT value, encrypted FROM settings WHERE key = ?`, key).Scan(&raw, &enc)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	if enc == 1 && raw != "" {
		dec, err := s.box.Decrypt(raw)
		if err != nil {
			return "", false, fmt.Errorf("decrypt setting %s: %w", key, err)
		}
		return dec, true, nil
	}
	return raw, true, nil
}

func DefaultSettings() AppSettings {
	return AppSettings{
		IMAPHost:            "imap.mail.me.com",
		IMAPPort:            993,
		AIProvider:          "typesafe",
		AIModel:             "jev-latest",
		SpamAction:          "trash",
		TrashThreshold:      0.85,
		DeleteThreshold:     0.95,
		AbuseEnabled:        true,
		AbuseManualApproval: true,
		AbuseMinConfidence:  0.95,
		AbuseCooldownDays:   7,
		AbuseSMTPMode:       "icloud_alias",
		AbuseSMTPHost:       "smtp.mail.me.com",
		AbuseSMTPPort:       587,
	}
}

func (s *Store) GetSettings() (AppSettings, error) {
	cfg := DefaultSettings()
	rows, err := s.db.Query(`SELECT key, value, encrypted FROM settings`)
	if err != nil {
		return cfg, err
	}
	defer rows.Close()

	for rows.Next() {
		var k, v string
		var enc int
		if err := rows.Scan(&k, &v, &enc); err != nil {
			return cfg, err
		}
		if enc == 1 && v != "" {
			dec, err := s.box.Decrypt(v)
			if err != nil {
				return cfg, fmt.Errorf("decrypt %s: %w", k, err)
			}
			v = dec
		}
		switch k {
		case "imap_host":
			if v != "" {
				cfg.IMAPHost = v
			}
		case "imap_port":
			if n, err := strconv.Atoi(v); err == nil && n > 0 {
				cfg.IMAPPort = n
			}
		case "imap_username":
			cfg.IMAPUsername = v
		case "imap_password":
			cfg.IMAPPassword = v
		case "ai_provider":
			if v != "" {
				cfg.AIProvider = v
			}
		case "ai_api_key":
			cfg.AIAPIKey = v
		case "ai_model":
			if v != "" {
				cfg.AIModel = v
			}
		case "spam_action":
			if v == "trash" || v == "delete" {
				cfg.SpamAction = v
			}
		case "trash_threshold":
			if f, err := strconv.ParseFloat(v, 64); err == nil {
				cfg.TrashThreshold = f
			}
		case "delete_threshold":
			if f, err := strconv.ParseFloat(v, 64); err == nil {
				cfg.DeleteThreshold = f
			}
		case "abuse_enabled":
			cfg.AbuseEnabled = v == "true"
		case "abuse_manual_approval":
			cfg.AbuseManualApproval = v != "false"
		case "abuse_min_confidence":
			if f, err := strconv.ParseFloat(v, 64); err == nil {
				cfg.AbuseMinConfidence = f
			}
		case "abuse_cooldown_days":
			if n, err := strconv.Atoi(v); err == nil && n > 0 {
				cfg.AbuseCooldownDays = n
			}
		case "abuse_smtp_mode":
			if v != "" {
				cfg.AbuseSMTPMode = v
			}
		case "abuse_from_email":
			cfg.AbuseFromEmail = v
		case "abuse_smtp_host":
			if v != "" {
				cfg.AbuseSMTPHost = v
			}
		case "abuse_smtp_port":
			if n, err := strconv.Atoi(v); err == nil && n > 0 {
				cfg.AbuseSMTPPort = n
			}
		case "abuse_smtp_username":
			cfg.AbuseSMTPUsername = v
		case "abuse_smtp_password":
			cfg.AbuseSMTPPassword = v
		}
	}
	return cfg, rows.Err()
}

func (s *Store) SaveSettings(cfg AppSettings) error {
	pairs := []struct {
		key       string
		value     string
		encrypted bool
	}{
		{"imap_host", cfg.IMAPHost, false},
		{"imap_port", strconv.Itoa(cfg.IMAPPort), false},
		{"imap_username", cfg.IMAPUsername, false},
		{"ai_provider", cfg.AIProvider, false},
		{"ai_model", cfg.AIModel, false},
		{"spam_action", cfg.SpamAction, false},
		{"trash_threshold", strconv.FormatFloat(cfg.TrashThreshold, 'f', 4, 64), false},
		{"delete_threshold", strconv.FormatFloat(cfg.DeleteThreshold, 'f', 4, 64), false},
		{"abuse_enabled", strconv.FormatBool(cfg.AbuseEnabled), false},
		{"abuse_manual_approval", strconv.FormatBool(cfg.AbuseManualApproval), false},
		{"abuse_min_confidence", strconv.FormatFloat(cfg.AbuseMinConfidence, 'f', 4, 64), false},
		{"abuse_cooldown_days", strconv.Itoa(cfg.AbuseCooldownDays), false},
		{"abuse_smtp_mode", cfg.AbuseSMTPMode, false},
		{"abuse_from_email", cfg.AbuseFromEmail, false},
		{"abuse_smtp_host", cfg.AbuseSMTPHost, false},
		{"abuse_smtp_port", strconv.Itoa(cfg.AbuseSMTPPort), false},
		{"abuse_smtp_username", cfg.AbuseSMTPUsername, false},
	}
	if cfg.IMAPPassword != "" {
		pairs = append(pairs, struct {
			key       string
			value     string
			encrypted bool
		}{"imap_password", cfg.IMAPPassword, true})
	}
	if cfg.AIAPIKey != "" {
		pairs = append(pairs, struct {
			key       string
			value     string
			encrypted bool
		}{"ai_api_key", cfg.AIAPIKey, true})
	}
	if cfg.AbuseSMTPPassword != "" {
		pairs = append(pairs, struct {
			key       string
			value     string
			encrypted bool
		}{"abuse_smtp_password", cfg.AbuseSMTPPassword, true})
	}
	for _, p := range pairs {
		if err := s.SetRawSetting(p.key, p.value, p.encrypted); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) GetMailboxCursor(mailbox string) (uidValidity uint32, lastUID uint32, err error) {
	if mailbox == "" {
		mailbox = "INBOX"
	}
	var v, u int64
	err = s.db.QueryRow(`SELECT uid_validity, last_uid FROM imap_cursors WHERE mailbox = ?`, mailbox).Scan(&v, &u)
	if errors.Is(err, sql.ErrNoRows) {
		if mailbox == "INBOX" {
			return s.GetIMAPCursor()
		}
		return 0, 0, nil
	}
	if err != nil {
		return 0, 0, err
	}
	return uint32(v), uint32(u), nil
}

func (s *Store) SetMailboxCursor(mailbox string, uidValidity, lastUID uint32) error {
	if mailbox == "" {
		mailbox = "INBOX"
	}
	_, err := s.db.Exec(
		`INSERT INTO imap_cursors(mailbox, uid_validity, last_uid) VALUES(?, ?, ?)
		 ON CONFLICT(mailbox) DO UPDATE SET uid_validity=excluded.uid_validity, last_uid=excluded.last_uid`,
		mailbox, uidValidity, lastUID,
	)
	return err
}

func (s *Store) GetIMAPCursor() (uidValidity uint32, lastUID uint32, err error) {
	vStr, _, err := s.GetRawSetting("imap_uid_validity")
	if err != nil {
		return 0, 0, err
	}
	uStr, _, err := s.GetRawSetting("imap_last_uid")
	if err != nil {
		return 0, 0, err
	}
	if vStr != "" {
		if n, parseErr := strconv.ParseUint(vStr, 10, 32); parseErr == nil {
			uidValidity = uint32(n)
		}
	}
	if uStr != "" {
		if n, parseErr := strconv.ParseUint(uStr, 10, 32); parseErr == nil {
			lastUID = uint32(n)
		}
	}
	return uidValidity, lastUID, nil
}

func (s *Store) SetIMAPCursor(uidValidity, lastUID uint32) error {
	if err := s.SetRawSetting("imap_uid_validity", strconv.FormatUint(uint64(uidValidity), 10), false); err != nil {
		return err
	}
	return s.SetRawSetting("imap_last_uid", strconv.FormatUint(uint64(lastUID), 10), false)
}

func (s *Store) ListCategories() ([]Category, error) {
	rows, err := s.db.Query(`SELECT id, name, description, enabled, builtin, abuse_eligible, created_at FROM categories ORDER BY builtin DESC, name ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []Category
	for rows.Next() {
		var c Category
		var enabled, builtin, abuse int
		if err := rows.Scan(&c.ID, &c.Name, &c.Description, &enabled, &builtin, &abuse, &c.CreatedAt); err != nil {
			return nil, err
		}
		c.Enabled = enabled == 1
		c.Builtin = builtin == 1
		c.AbuseEligible = abuse == 1
		out = append(out, c)
	}
	return out, rows.Err()
}

func (s *Store) UpsertCategory(c Category) error {
	if c.CreatedAt == "" {
		c.CreatedAt = time.Now().UTC().Format(time.RFC3339)
	}
	_, err := s.db.Exec(
		`INSERT INTO categories(id, name, description, enabled, builtin, abuse_eligible, created_at) VALUES(?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT(id) DO UPDATE SET name=excluded.name, description=excluded.description, enabled=excluded.enabled, abuse_eligible=excluded.abuse_eligible`,
		c.ID, c.Name, c.Description, boolToInt(c.Enabled), boolToInt(c.Builtin), boolToInt(c.AbuseEligible), c.CreatedAt,
	)
	return err
}

func (s *Store) DeleteCategory(id string) error {
	res, err := s.db.Exec(`DELETE FROM categories WHERE id = ? AND builtin = 0`, id)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return errors.New("category not found or is built-in")
	}
	return nil
}

func (s *Store) ListAllowlist() ([]AllowlistEntry, error) {
	rows, err := s.db.Query(`SELECT id, pattern, kind, created_at FROM allowlist ORDER BY pattern ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []AllowlistEntry
	for rows.Next() {
		var e AllowlistEntry
		if err := rows.Scan(&e.ID, &e.Pattern, &e.Kind, &e.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

func (s *Store) AddAllowlistEntry(pattern, kind string) (AllowlistEntry, error) {
	clean := strings.ToLower(strings.TrimSpace(pattern))
	if clean == "" {
		return AllowlistEntry{}, errors.New("pattern cannot be empty")
	}
	if kind != "email" && kind != "domain" {
		if strings.Contains(clean, "@") {
			kind = "email"
		} else {
			kind = "domain"
		}
	}
	now := time.Now().UTC().Format(time.RFC3339)
	res, err := s.db.Exec(`INSERT INTO allowlist(pattern, kind, created_at) VALUES(?, ?, ?)`, clean, kind, now)
	if err != nil {
		return AllowlistEntry{}, err
	}
	id, _ := res.LastInsertId()
	return AllowlistEntry{ID: id, Pattern: clean, Kind: kind, CreatedAt: now}, nil
}

func (s *Store) DeleteAllowlistEntry(id int64) error {
	_, err := s.db.Exec(`DELETE FROM allowlist WHERE id = ?`, id)
	return err
}

func (s *Store) IsAllowlisted(senderEmail, senderDomain string) (bool, error) {
	email := strings.ToLower(strings.TrimSpace(senderEmail))
	domain := strings.ToLower(strings.TrimSpace(senderDomain))
	var count int
	err := s.db.QueryRow(
		`SELECT COUNT(1) FROM allowlist WHERE (kind = 'email' AND pattern = ?) OR (kind = 'domain' AND (pattern = ? OR ? LIKE '%.' || pattern))`,
		email, domain, domain,
	).Scan(&count)
	return count > 0, err
}

func (s *Store) HasEmailEvent(mailbox string, uidValidity, uid uint32) (bool, error) {
	if mailbox == "" {
		mailbox = "INBOX"
	}
	var count int
	err := s.db.QueryRow(`SELECT COUNT(1) FROM email_events WHERE mailbox = ? AND uid_validity = ? AND uid = ?`, mailbox, uidValidity, uid).Scan(&count)
	return count > 0, err
}

func (s *Store) RecordEmailEvent(ev EmailEvent) error {
	if ev.Mailbox == "" {
		ev.Mailbox = "INBOX"
	}
	if ev.ProcessedAt == "" {
		ev.ProcessedAt = time.Now().UTC().Format(time.RFC3339)
	}
	_, err := s.db.Exec(
		`INSERT OR IGNORE INTO email_events(mailbox, uid_validity, uid, message_id, sender, sender_domain, subject, email_date, processed_at, category_id, confidence, action, source)
		 VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		ev.Mailbox, ev.UIDValidity, ev.UID, ev.MessageID, ev.Sender, ev.SenderDomain, ev.Subject,
		ev.EmailDate, ev.ProcessedAt, ev.CategoryID, ev.Confidence, ev.Action, ev.Source,
	)
	return err
}

func (s *Store) DailySpamStats(days int) ([]DailyCategoryStat, error) {
	query := `SELECT substr(e.email_date, 1, 10) AS day, e.category_id, COALESCE(c.name, e.category_id) AS cat_name, COUNT(1) AS cnt
		FROM email_events e
		LEFT JOIN categories c ON c.id = e.category_id
		WHERE e.action IN ('trash', 'delete') AND e.category_id != ''`
	var args []any
	if days > 0 {
		since := time.Now().UTC().AddDate(0, 0, -days).Format("2006-01-02")
		query += ` AND substr(e.email_date, 1, 10) >= ?`
		args = append(args, since)
	}
	query += ` GROUP BY day, e.category_id ORDER BY day ASC, cat_name ASC`

	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []DailyCategoryStat
	for rows.Next() {
		var st DailyCategoryStat
		if err := rows.Scan(&st.Day, &st.CategoryID, &st.CategoryName, &st.Count); err != nil {
			return nil, err
		}
		out = append(out, st)
	}
	return out, rows.Err()
}

func (s *Store) SaveScanJob(job ScanJob) error {
	now := time.Now().UTC().Format(time.RFC3339)
	if job.CreatedAt == "" {
		job.CreatedAt = now
	}
	job.UpdatedAt = now
	if job.Checkpoints == nil {
		job.Checkpoints = map[string]uint32{}
	}
	if job.Summary == nil {
		job.Summary = map[string]int{}
	}
	if job.Samples == nil {
		job.Samples = []ScanSample{}
	}
	cpBytes, _ := json.Marshal(job.Checkpoints)
	summaryBytes, _ := json.Marshal(job.Summary)
	samplesBytes, _ := json.Marshal(job.Samples)
	_, err := s.db.Exec(
		`INSERT INTO scan_jobs(id, date_range, dry_run, rate_per_sec, status, current_mailbox, total_messages, scanned_messages, spam_found, last_uid, checkpoints_json, summary_json, samples_json, error_msg, created_at, updated_at)
		 VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT(id) DO UPDATE SET status=excluded.status, current_mailbox=excluded.current_mailbox, total_messages=excluded.total_messages, scanned_messages=excluded.scanned_messages, spam_found=excluded.spam_found, last_uid=excluded.last_uid, checkpoints_json=excluded.checkpoints_json, summary_json=excluded.summary_json, samples_json=excluded.samples_json, error_msg=excluded.error_msg, updated_at=excluded.updated_at`,
		job.ID, job.DateRange, boolToInt(job.DryRun), job.RatePerSec, job.Status, job.CurrentMailbox,
		job.TotalMessages, job.ScannedMessages, job.SpamFound, job.LastUID, string(cpBytes),
		string(summaryBytes), string(samplesBytes), job.ErrorMsg, job.CreatedAt, job.UpdatedAt,
	)
	return err
}

func (s *Store) GetLatestScanJob() (*ScanJob, error) {
	row := s.db.QueryRow(`SELECT id, date_range, dry_run, rate_per_sec, status, current_mailbox, total_messages, scanned_messages, spam_found, last_uid, checkpoints_json, summary_json, samples_json, error_msg, created_at, updated_at FROM scan_jobs ORDER BY created_at DESC LIMIT 1`)
	return scanJobFromRow(row)
}

func (s *Store) GetScanJob(id string) (*ScanJob, error) {
	row := s.db.QueryRow(`SELECT id, date_range, dry_run, rate_per_sec, status, current_mailbox, total_messages, scanned_messages, spam_found, last_uid, checkpoints_json, summary_json, samples_json, error_msg, created_at, updated_at FROM scan_jobs WHERE id = ?`, id)
	return scanJobFromRow(row)
}

func scanJobFromRow(row *sql.Row) (*ScanJob, error) {
	var j ScanJob
	var dryRun int
	var cpJSON, sumJSON, sampJSON string
	err := row.Scan(&j.ID, &j.DateRange, &dryRun, &j.RatePerSec, &j.Status, &j.CurrentMailbox, &j.TotalMessages, &j.ScannedMessages, &j.SpamFound, &j.LastUID, &cpJSON, &sumJSON, &sampJSON, &j.ErrorMsg, &j.CreatedAt, &j.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	j.DryRun = dryRun == 1
	j.Checkpoints = map[string]uint32{}
	_ = json.Unmarshal([]byte(cpJSON), &j.Checkpoints)
	j.Summary = map[string]int{}
	_ = json.Unmarshal([]byte(sumJSON), &j.Summary)
	_ = json.Unmarshal([]byte(sampJSON), &j.Samples)
	return &j, nil
}

func (s *Store) IsAbuseDismissed(rootDomain string) (bool, error) {
	var count int
	err := s.db.QueryRow(`SELECT COUNT(1) FROM abuse_dismissed WHERE root_domain = ?`, strings.ToLower(rootDomain)).Scan(&count)
	return count > 0, err
}

func (s *Store) DismissAbuseDomain(rootDomain string) error {
	clean := strings.ToLower(strings.TrimSpace(rootDomain))
	now := time.Now().UTC().Format(time.RFC3339)
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	if _, err := tx.Exec(`INSERT OR REPLACE INTO abuse_dismissed(root_domain, dismissed_at) VALUES(?, ?)`, clean, now); err != nil {
		_ = tx.Rollback()
		return err
	}
	if _, err := tx.Exec(`DELETE FROM abuse_queue WHERE root_domain = ?`, clean); err != nil {
		_ = tx.Rollback()
		return err
	}
	return tx.Commit()
}

func (s *Store) LastAbuseReportTime(rootDomain string) (time.Time, bool, error) {
	var ts string
	err := s.db.QueryRow(
		`SELECT reported_at FROM abuse_history WHERE root_domain = ? AND status = 'sent' ORDER BY reported_at DESC LIMIT 1`,
		strings.ToLower(rootDomain),
	).Scan(&ts)
	if errors.Is(err, sql.ErrNoRows) {
		return time.Time{}, false, nil
	}
	if err != nil {
		return time.Time{}, false, err
	}
	t, parseErr := time.Parse(time.RFC3339, ts)
	if parseErr != nil {
		return time.Time{}, false, parseErr
	}
	return t, true, nil
}

func (s *Store) UpsertAbuseQueueItem(item AbuseQueueItem) (AbuseQueueItem, error) {
	now := time.Now().UTC().Format(time.RFC3339)
	domain := strings.ToLower(strings.TrimSpace(item.RootDomain))
	targetsBytes, _ := json.Marshal(item.Targets)

	_, err := s.db.Exec(
		`INSERT INTO abuse_queue(root_domain, sending_ip, category_id, confidence, hit_count, targets_json, redacted_headers, subject, sender, repeat_offense, previous_reported_at, created_at, updated_at)
		 VALUES(?, ?, ?, ?, 1, ?, ?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT(root_domain) DO UPDATE SET
		   sending_ip=excluded.sending_ip,
		   category_id=excluded.category_id,
		   confidence=MAX(abuse_queue.confidence, excluded.confidence),
		   hit_count=abuse_queue.hit_count + 1,
		   targets_json=excluded.targets_json,
		   redacted_headers=excluded.redacted_headers,
		   subject=excluded.subject,
		   sender=excluded.sender,
		   repeat_offense=excluded.repeat_offense,
		   previous_reported_at=excluded.previous_reported_at,
		   updated_at=excluded.updated_at`,
		domain, item.SendingIP, item.CategoryID, item.Confidence, string(targetsBytes),
		item.RedactedHeaders, item.Subject, item.Sender, boolToInt(item.RepeatOffense),
		item.PreviousReportedAt, now, now,
	)
	if err != nil {
		return AbuseQueueItem{}, err
	}
	return s.GetAbuseQueueItemByDomain(domain)
}

func (s *Store) GetAbuseQueueItemByDomain(rootDomain string) (AbuseQueueItem, error) {
	row := s.db.QueryRow(`SELECT id, root_domain, sending_ip, category_id, confidence, hit_count, targets_json, redacted_headers, subject, sender, repeat_offense, previous_reported_at, created_at, updated_at FROM abuse_queue WHERE root_domain = ?`, strings.ToLower(rootDomain))
	return scanAbuseQueueItem(row)
}

func (s *Store) GetAbuseQueueItem(id int64) (AbuseQueueItem, error) {
	row := s.db.QueryRow(`SELECT id, root_domain, sending_ip, category_id, confidence, hit_count, targets_json, redacted_headers, subject, sender, repeat_offense, previous_reported_at, created_at, updated_at FROM abuse_queue WHERE id = ?`, id)
	return scanAbuseQueueItem(row)
}

func (s *Store) ListAbuseQueue() ([]AbuseQueueItem, error) {
	rows, err := s.db.Query(`SELECT id, root_domain, sending_ip, category_id, confidence, hit_count, targets_json, redacted_headers, subject, sender, repeat_offense, previous_reported_at, created_at, updated_at FROM abuse_queue ORDER BY updated_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []AbuseQueueItem
	for rows.Next() {
		var it AbuseQueueItem
		var targetsJSON string
		var repeat int
		if err := rows.Scan(&it.ID, &it.RootDomain, &it.SendingIP, &it.CategoryID, &it.Confidence, &it.HitCount, &targetsJSON, &it.RedactedHeaders, &it.Subject, &it.Sender, &repeat, &it.PreviousReportedAt, &it.CreatedAt, &it.UpdatedAt); err != nil {
			return nil, err
		}
		it.RepeatOffense = repeat == 1
		_ = json.Unmarshal([]byte(targetsJSON), &it.Targets)
		out = append(out, it)
	}
	return out, rows.Err()
}

func (s *Store) DeleteAbuseQueueItem(id int64) error {
	_, err := s.db.Exec(`DELETE FROM abuse_queue WHERE id = ?`, id)
	return err
}

func (s *Store) RecordAbuseHistory(entry AbuseHistoryEntry) error {
	if entry.ReportedAt == "" {
		entry.ReportedAt = time.Now().UTC().Format(time.RFC3339)
	}
	targetsBytes, _ := json.Marshal(entry.Targets)
	_, err := s.db.Exec(
		`INSERT INTO abuse_history(root_domain, sending_ip, category_id, hit_count, targets_json, status, error_msg, reported_at) VALUES(?, ?, ?, ?, ?, ?, ?, ?)`,
		strings.ToLower(entry.RootDomain), entry.SendingIP, entry.CategoryID, entry.HitCount, string(targetsBytes), entry.Status, entry.ErrorMsg, entry.ReportedAt,
	)
	return err
}

func (s *Store) GetRDAPCache(key string) ([]string, bool, error) {
	var raw, exp string
	err := s.db.QueryRow(`SELECT contacts_json, expires_at FROM rdap_cache WHERE lookup_key = ?`, key).Scan(&raw, &exp)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	expTime, err := time.Parse(time.RFC3339, exp)
	if err != nil || time.Now().UTC().After(expTime) {
		return nil, false, nil
	}
	var contacts []string
	if err := json.Unmarshal([]byte(raw), &contacts); err != nil {
		return nil, false, err
	}
	return contacts, true, nil
}

func (s *Store) SetRDAPCache(key string, contacts []string, ttl time.Duration) error {
	raw, _ := json.Marshal(contacts)
	exp := time.Now().UTC().Add(ttl).Format(time.RFC3339)
	_, err := s.db.Exec(
		`INSERT OR REPLACE INTO rdap_cache(lookup_key, contacts_json, expires_at) VALUES(?, ?, ?)`,
		key, string(raw), exp,
	)
	return err
}

func (s *Store) CreatePairedDevice(id, name, tokenHash string) (PairedDevice, error) {
	now := time.Now().UTC().Format(time.RFC3339)
	_, err := s.db.Exec(
		`INSERT INTO paired_devices(id, name, token_hash, created_at, last_seen_at) VALUES(?, ?, ?, ?, ?)`,
		id, name, tokenHash, now, now,
	)
	if err != nil {
		return PairedDevice{}, err
	}
	return PairedDevice{ID: id, Name: name, CreatedAt: now, LastSeenAt: now}, nil
}

func (s *Store) FindDeviceByTokenHash(tokenHash string) (*PairedDevice, error) {
	var d PairedDevice
	err := s.db.QueryRow(`SELECT id, name, created_at, last_seen_at FROM paired_devices WHERE token_hash = ?`, tokenHash).Scan(&d.ID, &d.Name, &d.CreatedAt, &d.LastSeenAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC().Format(time.RFC3339)
	_, _ = s.db.Exec(`UPDATE paired_devices SET last_seen_at = ? WHERE id = ?`, now, d.ID)
	d.LastSeenAt = now
	return &d, nil
}

func (s *Store) ListPairedDevices() ([]PairedDevice, error) {
	rows, err := s.db.Query(`SELECT id, name, created_at, last_seen_at FROM paired_devices ORDER BY created_at ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []PairedDevice
	for rows.Next() {
		var d PairedDevice
		if err := rows.Scan(&d.ID, &d.Name, &d.CreatedAt, &d.LastSeenAt); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

func (s *Store) DeletePairedDevice(id string) error {
	_, err := s.db.Exec(`DELETE FROM paired_devices WHERE id = ?`, id)
	return err
}

func (s *Store) CountPairedDevices() (int, error) {
	var count int
	err := s.db.QueryRow(`SELECT COUNT(1) FROM paired_devices`).Scan(&count)
	return count, err
}

func (s *Store) CreatePairingCode(codeHash string, ttl time.Duration) error {
	exp := time.Now().UTC().Add(ttl).Format(time.RFC3339)
	_, err := s.db.Exec(`INSERT OR REPLACE INTO pairing_codes(code_hash, expires_at, used) VALUES(?, ?, 0)`, codeHash, exp)
	return err
}

func (s *Store) ConsumePairingCode(codeHash string) (bool, error) {
	var exp string
	var used int
	err := s.db.QueryRow(`SELECT expires_at, used FROM pairing_codes WHERE code_hash = ?`, codeHash).Scan(&exp, &used)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if used == 1 {
		return false, nil
	}
	expTime, err := time.Parse(time.RFC3339, exp)
	if err != nil || time.Now().UTC().After(expTime) {
		return false, nil
	}
	_, err = s.db.Exec(`UPDATE pairing_codes SET used = 1 WHERE code_hash = ?`, codeHash)
	return err == nil, err
}

func scanAbuseQueueItem(row *sql.Row) (AbuseQueueItem, error) {
	var it AbuseQueueItem
	var targetsJSON string
	var repeat int
	err := row.Scan(&it.ID, &it.RootDomain, &it.SendingIP, &it.CategoryID, &it.Confidence, &it.HitCount, &targetsJSON, &it.RedactedHeaders, &it.Subject, &it.Sender, &repeat, &it.PreviousReportedAt, &it.CreatedAt, &it.UpdatedAt)
	if err != nil {
		return it, err
	}
	it.RepeatOffense = repeat == 1
	_ = json.Unmarshal([]byte(targetsJSON), &it.Targets)
	return it, nil
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
