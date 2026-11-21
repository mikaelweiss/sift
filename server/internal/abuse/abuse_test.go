package abuse

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"mime/multipart"
	"net"
	"net/http"
	"net/http/httptest"
	"net/mail"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mikaelweiss/sift/server/internal/db"
)

type mockSender struct {
	mu   sync.Mutex
	sent []Mail
	fail map[string]bool
}

func (m *mockSender) Send(_ context.Context, _ db.AppSettings, msg Mail) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sent = append(m.sent, msg)
	if m.fail[msg.To] {
		return errors.New("rejected")
	}
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

// fakeRDAP answers every IP lookup with abuse@host.<ip> and every domain lookup with abuse@registrar.<domain>.
func fakeRDAP(t *testing.T) *httptest.Server {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
		email := "abuse@registrar." + parts[1]
		if parts[0] == "ip" {
			email = "abuse@host-" + strings.ReplaceAll(parts[1], ".", "-") + ".example"
		}
		w.Header().Set("Content-Type", "application/rdap+json")
		_, _ = w.Write([]byte(`{"entities":[{"roles":["abuse"],"vcardArray":["vcard",[["email",{},"text","` + email + `"]]]}]}`))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func testResolver(t *testing.T, store *db.Store) *Resolver {
	r := NewResolver(store)
	r.rdapBase = fakeRDAP(t).URL
	r.whoisDial = nil
	r.lookupIP = func(_ context.Context, host string) ([]net.IPAddr, error) {
		return []net.IPAddr{{IP: net.ParseIP("203.0.113.77")}}, nil
	}
	return r
}

const sesPhish = "Received: from a1-2.smtp-out.amazonses.com (a1-2.smtp-out.amazonses.com [198.51.100.9]) by mx.icloud.com\r\n" +
	"Return-Path: <bounce@send.evil.test>\r\n" +
	"DKIM-Signature: v=1; a=rsa-sha256; d=amazonses.com; s=abc; b=xyz\r\n" +
	"From: \"Apple Support\" <support@evil.test>\r\n" +
	"To: alice@icloud.com\r\n" +
	"Subject: Your Apple ID is locked\r\n\r\n" +
	"Unlock at https://login.phish.test/apple and see https://www.google.com/x\r\n"

func TestResolveTargetsCoversEveryChannel(t *testing.T) {
	store, err := db.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	r := testResolver(t, store)
	cand := Candidate{
		SenderEmail: "support@evil.test", SenderDomain: "evil.test", From: `"Apple Support" <support@evil.test>`,
		Subject: "Your Apple ID is locked", RawMessage: sesPhish, LinkDomains: []string{"login.phish.test", "www.google.com"},
		CategoryID: "phishing_scams",
	}
	headers := headerBlock(sesPhish)
	targets := r.ResolveTargets(context.Background(), cand, headers, ExtractOriginatingIP(headers), "evil.test")

	got := map[string]string{}
	for _, tg := range targets {
		got[tg.Address] = tg.Kind
	}
	want := map[string]string{
		"abuse@host-198-51-100-9.example": KindNetwork,
		"abuse@registrar.evil.test":       KindRegistrar,
		"email-abuse@amazon.com":          KindEmailService,
		"abuse@host-203-0-113-77.example": KindLinkHost,
		"abuse@registrar.phish.test":      KindLinkRegistrar,
		"reportphishing@apwg.org":         KindClearinghouse,
		"reportphishing@apple.com":        KindApple,
		"report.netcraft.com":             KindNetcraft,
	}
	for addr, kind := range want {
		if got[addr] != kind {
			t.Errorf("missing %s (%s); got %v", addr, kind, got)
		}
	}
	for addr := range got {
		if strings.Contains(addr, "google") {
			t.Errorf("reported a skip-listed link domain: %s", addr)
		}
	}
}

func TestApprovedReportsSendInBackgroundAndRecordEachRecipient(t *testing.T) {
	store, err := db.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	cfg := db.DefaultSettings()
	cfg.AbuseManualApproval = true
	cfg.IMAPUsername = "alice@icloud.com"
	_ = store.SaveSettings(cfg)

	sender := &mockSender{fail: map[string]bool{"abuse@registrar.evil.test": true}}
	svc := NewService(store, testResolver(t, store), sender)
	var netcraftMessages []string
	svc.netcraft = func(_ context.Context, email, message string) error {
		netcraftMessages = append(netcraftMessages, message)
		return nil
	}
	now := time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)
	svc.nowFn = func() time.Time { return now }

	cand := Candidate{
		SenderEmail: "support@evil.test", SenderDomain: "evil.test", From: `"Apple Support" <support@evil.test>`,
		Subject: "Your Apple ID is locked", RawMessage: sesPhish, LinkDomains: []string{"login.phish.test"},
		CategoryID: "phishing_scams", Confidence: 0.98, EmailDate: now.Add(-time.Hour),
	}

	old := cand
	old.EmailDate = now.Add(-10 * 24 * time.Hour)
	_ = svc.Consider(context.Background(), old)
	if q, _ := store.ListAbuseQueue(); len(q) != 0 {
		t.Fatal("mail older than 7 days was queued")
	}

	_ = svc.Consider(context.Background(), cand)
	_ = svc.Consider(context.Background(), cand)
	q, _ := store.ListAbuseQueue()
	if len(q) != 1 || q[0].HitCount != 2 || q[0].Status != "pending" {
		t.Fatalf("queue %+v", q)
	}
	if strings.Contains(q[0].Evidence, "alice@icloud.com") {
		t.Fatal("evidence leaks the user's address")
	}

	if err := svc.Approve(q[0].ID); err != nil {
		t.Fatal(err)
	}
	if err := svc.Approve(q[0].ID); err == nil {
		t.Fatal("a second approval of a sending report succeeded")
	}
	svc.WaitForDeliveries()

	history, _ := store.ListAbuseHistory(10)
	if len(history) != 1 || history[0].Status != "partial" {
		t.Fatalf("history %+v", history)
	}
	failed := 0
	for _, d := range history[0].Deliveries {
		if !d.OK {
			failed++
			if d.Address != "abuse@registrar.evil.test" || d.Error == "" {
				t.Fatalf("wrong failed delivery %+v", d)
			}
		}
	}
	if failed != 1 || len(netcraftMessages) != 1 {
		t.Fatalf("failed %d deliveries, netcraft calls %d", failed, len(netcraftMessages))
	}
	for _, m := range sender.sent {
		if string(m.Attachment) == "" || m.AttachmentName != "evidence.eml" {
			t.Fatalf("report to %s has no evidence attached", m.To)
		}
	}
	if q, _ := store.ListAbuseQueue(); len(q) != 0 {
		t.Fatal("partially sent report stayed queued")
	}

	// Within the cooldown nothing queues. After it, a repeat offense whose every delivery fails returns to the queue.
	now = now.Add(3 * 24 * time.Hour)
	cand.EmailDate = now
	_ = svc.Consider(context.Background(), cand)
	if q, _ := store.ListAbuseQueue(); len(q) != 0 {
		t.Fatal("cooldown did not suppress the repeat")
	}
	now = now.Add(6 * 24 * time.Hour)
	cand.EmailDate = now
	sender.fail = map[string]bool{}
	svc.netcraft = func(context.Context, string, string) error { return errors.New("down") }
	_ = svc.Consider(context.Background(), cand)
	q, _ = store.ListAbuseQueue()
	if len(q) != 1 || !q[0].RepeatOffense {
		t.Fatalf("repeat offense not queued: %+v", q)
	}
	for _, tg := range q[0].Targets {
		if tg.Kind != KindNetcraft {
			sender.fail[tg.Address] = true
		}
	}
	_ = svc.Approve(q[0].ID)
	svc.WaitForDeliveries()
	q, _ = store.ListAbuseQueue()
	if len(q) != 1 || q[0].Status != "pending" {
		t.Fatalf("fully failed report did not return to the queue: %+v", q)
	}
}

func TestBuildMessageAttachesEvidence(t *testing.T) {
	raw := BuildMessage("alice@icloud.com", Mail{To: "abuse@host.example", Subject: "Report", Body: "Hello\nthere", Attachment: []byte(sesPhish), AttachmentName: "evidence.eml"})
	msg, err := mail.ReadMessage(bufio.NewReader(strings.NewReader(string(raw))))
	if err != nil {
		t.Fatal(err)
	}
	mediaType, params, err := mime.ParseMediaType(msg.Header.Get("Content-Type"))
	if err != nil || mediaType != "multipart/mixed" {
		t.Fatalf("content type %q: %v", mediaType, err)
	}
	mr := multipart.NewReader(msg.Body, params["boundary"])
	if _, err := mr.NextPart(); err != nil {
		t.Fatal(err)
	}
	att, err := mr.NextPart()
	if err != nil {
		t.Fatal(err)
	}
	if att.Header.Get("Content-Type") != `message/rfc822; name="evidence.eml"` {
		t.Fatalf("attachment type %q", att.Header.Get("Content-Type"))
	}
	decoded, _ := io.ReadAll(att)
	if strings.TrimRight(string(decoded), "\r\n") != strings.TrimRight(sesPhish, "\r\n") {
		t.Fatalf("attachment did not round-trip")
	}
}

func TestNetcraftReporterSendsRawMessage(t *testing.T) {
	var got map[string]string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method %s", r.Method)
		}
		_ = json.NewDecoder(r.Body).Decode(&got)
		_, _ = w.Write([]byte(`{"message":"Successfully reported","uuid":"abc"}`))
	}))
	defer srv.Close()
	n := &netcraftReporter{client: srv.Client(), endpoint: srv.URL}
	if err := n.Report(context.Background(), "alice@icloud.com", sesPhish); err != nil {
		t.Fatal(err)
	}
	if got["email"] != "alice@icloud.com" || got["message"] != sesPhish {
		t.Fatalf("payload %v", got)
	}

	reject := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"message":"Something else"}`))
	}))
	defer reject.Close()
	n.endpoint = reject.URL
	if err := n.Report(context.Background(), "alice@icloud.com", sesPhish); err == nil {
		t.Fatal("an unexpected Netcraft reply counted as success")
	}
}
