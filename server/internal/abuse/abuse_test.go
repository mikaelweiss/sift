package abuse

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/mikaelweiss/eclean/server/internal/db"
)

type mockSender struct {
	sentTo [][]string
}

func (m *mockSender) Send(_ context.Context, _ db.AppSettings, to []string, _, _ string) error {
	m.sentTo = append(m.sentTo, to)
	return nil
}

func TestExtractorAndRedaction(t *testing.T) {
	if got := RootDomain("sub.mail.evil-domain.co.uk"); got != "evil-domain.co.uk" {
		t.Fatalf("unexpected root domain: %s", got)
	}
	if !IsSharedMailProvider("gmail.com") || IsSharedMailProvider("evil.test") {
		t.Fatalf("shared provider detection failed")
	}

	headers := strings.Join([]string{
		"Received: from internal.icloud.com ([10.0.0.5]) by mail.icloud.com for <alice@icloud.com>; Fri, 20 Nov 2026 10:00:00 +0000",
		"Received: from spammer.evil.test ([198.51.100.42]) by mx.icloud.com for <alice@icloud.com>; Fri, 20 Nov 2026 09:59:58 +0000",
		"Delivered-To: alice@icloud.com",
		"To: Alice <alice@icloud.com>",
		"From: scam@evil.test",
	}, "\r\n")

	if ip := ExtractOriginatingIP(headers); ip != "198.51.100.42" {
		t.Fatalf("expected 198.51.100.42, got %q", ip)
	}

	redacted := RedactHeaders(headers, "alice@icloud.com")
	if strings.Contains(strings.ToLower(redacted), "alice@icloud.com") {
		t.Fatalf("user email leaked in redacted headers: %s", redacted)
	}
	if !strings.Contains(redacted, "From: scam@evil.test") {
		t.Fatalf("sender header unexpectedly removed: %s", redacted)
	}
}

func TestAbuseServiceQueueCooldownRepeatAndAutoSend(t *testing.T) {
	store, err := db.Open(t.TempDir())
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer store.Close()

	cfg := db.DefaultSettings()
	cfg.AbuseEnabled = true
	cfg.AbuseManualApproval = true
	cfg.AbuseMinConfidence = 0.95
	cfg.AbuseCooldownDays = 7
	cfg.IMAPUsername = "alice@icloud.com"
	_ = store.SaveSettings(cfg)

	rdapSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/rdap+json")
		if strings.HasPrefix(r.URL.Path, "/ip/") {
			_, _ = w.Write([]byte(`{"entities":[{"roles":["abuse"],"vcardArray":["vcard",[["email",{},"text","abuse@host.example"]]]}]}`))
			return
		}
		_, _ = w.Write([]byte(`{"entities":[{"roles":["abuse"],"vcardArray":["vcard",[["email",{},"text","abuse@registrar.example"]]]}]}`))
	}))
	defer rdapSrv.Close()

	resolver := NewResolver(store)
	resolver.rdapBase = rdapSrv.URL
	resolver.whoisDial = nil

	sender := &mockSender{}
	svc := NewService(store, resolver, sender)
	now := time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)
	svc.nowFn = func() time.Time { return now }

	rawHdr := "Received: from host.evil.test ([198.51.100.9]) by mx.icloud.com\r\nTo: alice@icloud.com\r\nFrom: bad@evil.test\r\n"
	cand := Candidate{
		SenderEmail:  "bad@evil.test",
		SenderDomain: "evil.test",
		Subject:      "Urgent wire",
		RawHeaders:   rawHdr,
		CategoryID:   "phishing_scams",
		Confidence:   0.98,
		EmailDate:    now.Add(-2 * time.Hour),
	}

	// Old email (>7d) must be ignored.
	oldCand := cand
	oldCand.EmailDate = now.Add(-10 * 24 * time.Hour)
	if err := svc.Consider(context.Background(), oldCand); err != nil {
		t.Fatalf("old consider: %v", err)
	}
	if q, _ := store.ListAbuseQueue(); len(q) != 0 {
		t.Fatalf("old email should not queue")
	}

	// Queue twice -> deduplicates with hit_count=2.
	if err := svc.Consider(context.Background(), cand); err != nil {
		t.Fatalf("first consider: %v", err)
	}
	if err := svc.Consider(context.Background(), cand); err != nil {
		t.Fatalf("second consider: %v", err)
	}
	q, _ := store.ListAbuseQueue()
	if len(q) != 1 || q[0].HitCount != 2 || len(q[0].Targets) != 2 {
		t.Fatalf("unexpected queue state: %+v", q)
	}

	// Approve and send.
	if _, err := svc.ApproveAndSend(context.Background(), q[0].ID); err != nil {
		t.Fatalf("ApproveAndSend: %v", err)
	}
	if len(sender.sentTo) != 1 {
		t.Fatalf("expected 1 send, got %d", len(sender.sentTo))
	}

	// Within 7-day cooldown -> skipped.
	now = now.Add(3 * 24 * time.Hour)
	cand.EmailDate = now
	_ = svc.Consider(context.Background(), cand)
	if q, _ := store.ListAbuseQueue(); len(q) != 0 {
		t.Fatalf("expected cooldown to skip re-queue")
	}

	// After 8 days -> re-queued as repeat offense, and test auto-send mode.
	cfg.AbuseManualApproval = false
	_ = store.SaveSettings(cfg)
	now = now.Add(6 * 24 * time.Hour)
	cand.EmailDate = now
	if err := svc.Consider(context.Background(), cand); err != nil {
		t.Fatalf("repeat auto-send consider: %v", err)
	}
	if len(sender.sentTo) != 2 {
		t.Fatalf("expected auto-send to fire second report, got %d", len(sender.sentTo))
	}
}
