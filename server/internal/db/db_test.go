package db

import (
	"testing"
	"time"
)

func TestStoreLifecycle(t *testing.T) {
	dir := t.TempDir()
	store, err := Open(dir)
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer store.Close()

	cats, err := store.ListCategories()
	if err != nil {
		t.Fatalf("ListCategories: %v", err)
	}
	if len(cats) != 7 {
		t.Fatalf("expected 7 seeded builtin categories, got %d", len(cats))
	}

	cfg := DefaultSettings()
	cfg.IMAPUsername = "alice@icloud.com"
	cfg.IMAPPassword = "abcd-efgh-ijkl-mnop"
	cfg.AIProvider = "openrouter"
	cfg.AIAPIKey = "sk-or-test-key"
	cfg.SpamAction = "delete"
	if err := store.SaveSettings(cfg); err != nil {
		t.Fatalf("SaveSettings: %v", err)
	}

	loaded, err := store.GetSettings()
	if err != nil {
		t.Fatalf("GetSettings: %v", err)
	}
	if loaded.IMAPPassword != cfg.IMAPPassword || loaded.AIAPIKey != cfg.AIAPIKey || loaded.SpamAction != "delete" {
		t.Fatalf("settings round-trip mismatch: %+v", loaded)
	}

	if _, err := store.AddAllowlistEntry("example.com", "domain"); err != nil {
		t.Fatalf("AddAllowlistEntry: %v", err)
	}
	ok, err := store.IsAllowlisted("user@sub.example.com", "sub.example.com")
	if err != nil || !ok {
		t.Fatalf("expected subdomain allowlist match, ok=%v err=%v", ok, err)
	}

	today := time.Now().UTC().Format(time.RFC3339)
	ev := EmailEvent{
		UIDValidity:  10,
		UID:          42,
		Sender:       "scam@evil.test",
		SenderDomain: "evil.test",
		Subject:      "Claim prize",
		EmailDate:    today,
		CategoryID:   "phishing_scams",
		Confidence:   0.98,
		Action:       "trash",
		Source:       "realtime",
	}
	if err := store.RecordEmailEvent(ev); err != nil {
		t.Fatalf("RecordEmailEvent: %v", err)
	}
	if err := store.RecordEmailEvent(ev); err != nil {
		t.Fatalf("duplicate RecordEmailEvent should ignore: %v", err)
	}

	stats, err := store.DailySpamStats(30)
	if err != nil {
		t.Fatalf("DailySpamStats: %v", err)
	}
	if len(stats) != 1 || stats[0].Count != 1 {
		t.Fatalf("unexpected stats: %+v", stats)
	}

	q1, err := store.UpsertAbuseQueueItem(AbuseQueueItem{
		RootDomain:      "evil.test",
		SendingIP:       "203.0.113.5",
		CategoryID:      "phishing_scams",
		Confidence:      0.96,
		Targets:         []string{"abuse@registrar.test"},
		RedactedHeaders: "From: scam@evil.test",
		Subject:         "Claim prize",
		Sender:          "scam@evil.test",
	})
	if err != nil || q1.HitCount != 1 {
		t.Fatalf("first UpsertAbuseQueueItem: %+v err=%v", q1, err)
	}
	q2, err := store.UpsertAbuseQueueItem(AbuseQueueItem{
		RootDomain:      "evil.test",
		SendingIP:       "203.0.113.6",
		CategoryID:      "phishing_scams",
		Confidence:      0.99,
		Targets:         []string{"abuse@registrar.test"},
		RedactedHeaders: "From: scam2@evil.test",
		Subject:         "Second scam",
		Sender:          "scam2@evil.test",
	})
	if err != nil || q2.HitCount != 2 || q2.Confidence != 0.99 {
		t.Fatalf("dedup UpsertAbuseQueueItem: %+v err=%v", q2, err)
	}

	if err := store.DismissAbuseDomain("evil.test"); err != nil {
		t.Fatalf("DismissAbuseDomain: %v", err)
	}
	dismissed, err := store.IsAbuseDismissed("evil.test")
	if err != nil || !dismissed {
		t.Fatalf("expected dismissed domain")
	}

	if err := store.CreatePairingCode("hash123", time.Minute); err != nil {
		t.Fatalf("CreatePairingCode: %v", err)
	}
	consumed, err := store.ConsumePairingCode("hash123")
	if err != nil || !consumed {
		t.Fatalf("expected pairing code to consume once")
	}
	consumedAgain, err := store.ConsumePairingCode("hash123")
	if err != nil || consumedAgain {
		t.Fatalf("pairing code must not be reusable")
	}

	if err := store.RecordScanResults([]ScanResult{
		{
			JobID:        "job-1",
			Mailbox:      "Archive",
			UIDValidity:  9,
			UID:          101,
			Sender:       "spam@bad.test",
			SenderDomain: "bad.test",
			Subject:      "Deal",
			EmailDate:    today,
			CategoryID:   "marketing_promotions",
			Confidence:   0.92,
			Action:       "trash",
		},
	}); err != nil {
		t.Fatalf("RecordScanResults: %v", err)
	}
	pending, err := store.ListPendingScanResults("job-1")
	if err != nil || len(pending) != 1 {
		t.Fatalf("expected 1 pending scan result, got %d err=%v", len(pending), err)
	}
	if err := store.MarkScanResultsApplied([]int64{pending[0].ID}); err != nil {
		t.Fatalf("MarkScanResultsApplied: %v", err)
	}
	pendingAfter, err := store.ListPendingScanResults("job-1")
	if err != nil || len(pendingAfter) != 0 {
		t.Fatalf("expected 0 pending scan results after mark applied, got %d", len(pendingAfter))
	}
}
