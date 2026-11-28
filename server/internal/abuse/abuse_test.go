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
	"github.com/mikaelweiss/sift/server/internal/jev"
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

func TestFormOnlyAbuseDesksAreSkipped(t *testing.T) {
	for address, want := range map[string]bool{
		"abuse@ovh.net":                             false,
		"rtr-security-threats@realtimeregister.com": false,
		"abuse@cloudflare.com":                      false,
		"abuse@mail.ovhcloud.com":                   false,
		"abuse@dynadot.com":                         false,
		"abuse@registrar.eu":                        false,
		"abuse-info@openprovider.nl":                false,
		"abuse@openprovider.com":                    false,
		"abuse@hosting.international":               true,
	} {
		if got := acceptsEmailReports(address); got != want {
			t.Errorf("acceptsEmailReports(%q) = %v, want %v", address, got, want)
		}
	}
}

func TestSharedProvidersLinkSkipsAndAWSDedupe(t *testing.T) {
	if !IsSharedMailProvider("att.net") {
		t.Fatal("att.net should be treated as a shared mail provider")
	}
	if links := reportableLinkDomains([]string{"s.yusercontent.com", "evil-link.test"}, "spam.test"); len(links) != 1 || links[0] != "evil-link.test" {
		t.Fatalf("unexpected reportable links: %v", links)
	}

	store, err := db.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/rdap+json")
		_, _ = w.Write([]byte(`{"entities":[{"roles":["abuse"],"vcardArray":["vcard",[["email",{},"text","trustandsafety@support.aws.com"]]]}]}`))
	}))
	defer srv.Close()

	r := NewResolver(store)
	r.rdapBase = srv.URL
	r.whoisDial = nil
	r.lookupIP = func(_ context.Context, _ string) ([]net.IPAddr, error) {
		return []net.IPAddr{{IP: net.ParseIP("54.240.8.71")}}, nil
	}
	cand := Candidate{
		SenderEmail: "hello@evil.test", SenderDomain: "evil.test", From: "hello@evil.test",
		Subject: "Test", RawMessage: sesPhish, LinkDomains: []string{"link.evil.test"},
		CategoryID: "phishing_scams",
	}
	targets := r.ResolveTargets(context.Background(), cand, headerBlock(sesPhish), "54.240.8.71", "evil.test")
	hasSES, hasAWS := false, false
	for _, tg := range targets {
		if tg.Address == "email-abuse@amazon.com" {
			hasSES = true
		}
		if tg.Address == "trustandsafety@support.aws.com" {
			hasAWS = true
		}
	}
	if !hasSES || hasAWS {
		t.Fatalf("expected email-abuse@amazon.com without trustandsafety@support.aws.com, got %+v", targets)
	}
}

func TestBuildMessageAWSPlainTextAndMessageID(t *testing.T) {
	msgID := NewReportMessageID("alice@icloud.com")
	if !strings.HasPrefix(msgID, "<sift-abuse-") || !strings.HasSuffix(msgID, "@icloud.com>") {
		t.Fatalf("unexpected message ID %q", msgID)
	}
	raw := BuildMessage("alice@icloud.com", Mail{
		MessageID:             msgID,
		To:                    "trustandsafety@support.aws.com",
		Subject:               "[Abuse Report] Phishing / scam from evil.test",
		Body:                  "Hello",
		Attachment:            []byte(sesPhish),
		AttachmentName:        "evidence.txt",
		AttachmentContentType: "text/plain",
	})
	msg, err := mail.ReadMessage(bufio.NewReader(strings.NewReader(string(raw))))
	if err != nil {
		t.Fatal(err)
	}
	if msg.Header.Get("Message-ID") != msgID {
		t.Fatalf("Message-ID mismatch: got %q want %q", msg.Header.Get("Message-ID"), msgID)
	}
	_, params, err := mime.ParseMediaType(msg.Header.Get("Content-Type"))
	if err != nil {
		t.Fatal(err)
	}
	mr := multipart.NewReader(msg.Body, params["boundary"])
	_, _ = mr.NextPart()
	att, err := mr.NextPart()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(att.Header.Get("Content-Type"), "text/plain") {
		t.Fatalf("expected text/plain attachment, got %q", att.Header.Get("Content-Type"))
	}
}

type fakeReplyEvaluator struct {
	calls int
	fn    func(state map[string]any) map[string]float64
}

func (f *fakeReplyEvaluator) EvaluateNoul(_ context.Context, state any, _ map[string]jev.NoulQuestion) (map[string]float64, error) {
	f.calls++
	m, _ := state.(map[string]any)
	return f.fn(m), nil
}

func (f *fakeReplyEvaluator) VerifyKey(_ context.Context) error { return nil }

func TestHandleIncomingRepliesBansFormOnlyAndBounces(t *testing.T) {
	store, err := db.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	cfg := db.DefaultSettings()
	cfg.IMAPUsername = "alice@icloud.com"
	_ = store.SaveSettings(cfg)

	sentMsgID := "<sift-abuse-deadbeef0102@icloud.com>"
	if err := store.RecordAbuseHistory(db.AbuseHistoryEntry{
		RootDomain: "formtarget.test",
		SendingIP:  "198.51.100.1",
		CategoryID: "phishing_scams",
		HitCount:   1,
		Subject:    "Scam",
		Sender:     "bad@formtarget.test",
		Deliveries: []db.AbuseDelivery{
			{
				AbuseTarget: db.AbuseTarget{Address: "abuse@registrar-alias.example", Kind: KindRegistrar, Reason: "Registrar"},
				MessageID:   db.NormalizeMessageID(sentMsgID),
				OK:          true,
			},
		},
		Status: "sent",
	}); err != nil {
		t.Fatal(err)
	}

	eval := &fakeReplyEvaluator{
		fn: func(state map[string]any) map[string]float64 {
			body := strings.ToLower(state["body_snippet"].(string))
			switch {
			case strings.Contains(body, "has been suspended"), strings.Contains(body, "violated the microsoft services agreement"):
				return map[string]float64{"is_abuse_reply": 0.98, "action_taken": 0.96, "form_only": 0.02}
			case strings.Contains(body, "do not accept abuse reports via email"):
				return map[string]float64{"is_abuse_reply": 0.97, "action_taken": 0.01, "form_only": 0.95}
			default:
				return map[string]float64{"is_abuse_reply": 0.92, "action_taken": 0.05, "form_only": 0.05}
			}
		},
	}

	svc := NewService(store, NewResolver(store), &mockSender{})
	svc.evaluator = eval
	var banCallbacks []int
	svc.OnBanRecorded = func(count int) { banCallbacks = append(banCallbacks, count) }

	// 1. Shock Hosting ban confirmation (no In-Reply-To).
	handled, rep, err := svc.HandleIncoming(context.Background(), ReplyInput{
		MessageID:    "<shock-1@shockhosting.com>",
		From:         "Shock Hosting Abuse <abuse@shockhosting.com>",
		SenderEmail:  "abuse@shockhosting.com",
		SenderDomain: "shockhosting.com",
		Subject:      "[Ticket ID: 708487] [Abuse Report] Unsolicited bulk email from mostbau.com",
		BodySnippet:  "Hello,\n\nThank you for bringing this to our attention!\n\nThe reported server has been suspended.",
	})
	if err != nil || !handled || rep == nil || rep.Outcome != OutcomeActionTaken || rep.ReportedDomain != "mostbau.com" {
		t.Fatalf("shock ban unexpected: handled=%v rep=%+v err=%v", handled, rep, err)
	}

	// 2. Shock Hosting ticket closed (same domain, should not increment bans).
	handled, rep, err = svc.HandleIncoming(context.Background(), ReplyInput{
		MessageID:    "<shock-2@shockhosting.com>",
		From:         "Shock Hosting Abuse <abuse@shockhosting.com>",
		SenderEmail:  "abuse@shockhosting.com",
		SenderDomain: "shockhosting.com",
		Subject:      "[Ticket ID: 708487] [Abuse Report] Unsolicited bulk email from mostbau.com",
		BodySnippet:  "This is a notification that we are changing the status of your ticket to Closed.",
	})
	if err != nil || !handled || rep == nil || rep.Outcome != OutcomeAcknowledged {
		t.Fatalf("shock close unexpected: handled=%v rep=%+v err=%v", handled, rep, err)
	}

	// 3. Microsoft Online Safety ban confirmation.
	handled, rep, err = svc.HandleIncoming(context.Background(), ReplyInput{
		MessageID:    "<ms-1@microsoft.com>",
		From:         "CDOC Case Management <cdoccm@microsoft.com>",
		SenderEmail:  "cdoccm@microsoft.com",
		SenderDomain: "microsoft.com",
		Subject:      "SIR25360475 - [Abuse Report] Unsolicited bulk email from outlook.com",
		BodySnippet:  "Hi,\nWe found it violated the Microsoft Services Agreement and taken appropriate action based on the reported violation.",
	})
	if err != nil || !handled || rep == nil || rep.Outcome != OutcomeActionTaken || rep.ReportedDomain != "outlook.com" {
		t.Fatalf("microsoft ban unexpected: handled=%v rep=%+v err=%v", handled, rep, err)
	}

	// 4. Auto-learned form-only desk via In-Reply-To learns both target alias and responder domain.
	handled, rep, err = svc.HandleIncoming(context.Background(), ReplyInput{
		MessageID:    "<form-1@desk-reply.example>",
		InReplyTo:    sentMsgID,
		From:         "Abuse <noreply@desk-reply.example>",
		SenderEmail:  "noreply@desk-reply.example",
		SenderDomain: "desk-reply.example",
		Subject:      "Auto-Reply: [Abuse Report] Phishing / scam from formtarget.test",
		BodySnippet:  "Please note we do not accept abuse reports via email. Use our web form.",
	})
	if err != nil || !handled || rep == nil || rep.Outcome != OutcomeFormOnly {
		t.Fatalf("form-only unexpected: handled=%v rep=%+v err=%v", handled, rep, err)
	}
	if svc.resolver.acceptsEmailReports("abuse@registrar-alias.example") || svc.resolver.acceptsEmailReports("abuse@desk-reply.example") {
		t.Fatal("learned form-only domains were not skipped by resolver")
	}

	// 5. iCloud DSN bounce handled without calling Jev.
	callsBefore := eval.calls
	bounceRaw := "Original-Recipient: rfc822;abuse@enom.com\r\nDiagnostic-Code: smtp; 550 5.7.1 [CS101] Message rejected due to local policy\r\n\r\nSubject: [Abuse Report] Phishing / scam from eliteneuromonitoring.com\r\nContent-Type: multipart/mixed; boundary=\"sift-abc123\"\r\n"
	handled, rep, err = svc.HandleIncoming(context.Background(), ReplyInput{
		MessageID:    "<bounce-1@outbound.ms.icloud.com>",
		From:         "Mail Delivery System <mailer-daemon@icloud.com>",
		SenderEmail:  "mailer-daemon@icloud.com",
		SenderDomain: "icloud.com",
		Subject:      "Undelivered Mail Returned to Sender",
		RawMessage:   bounceRaw,
	})
	if err != nil || !handled || rep == nil || rep.Outcome != OutcomeBounced || rep.ReportedDomain != "eliteneuromonitoring.com" || rep.TargetAddress != "abuse@enom.com" {
		t.Fatalf("bounce unexpected: handled=%v rep=%+v err=%v", handled, rep, err)
	}
	if eval.calls != callsBefore {
		t.Fatal("DSN bounce should not call Jev")
	}

	// 6. Unrelated newsletter does not match and does not call Jev.
	handled, rep, err = svc.HandleIncoming(context.Background(), ReplyInput{
		MessageID:    "<news-1@primeintellect.ai>",
		From:         "Prime Intellect <support@primeintellect.ai>",
		SenderEmail:  "support@primeintellect.ai",
		SenderDomain: "primeintellect.ai",
		Subject:      "Introducing Model Factory",
		BodySnippet:  "On-demand training and inference.",
	})
	if err != nil || handled || rep != nil || eval.calls != callsBefore {
		t.Fatalf("unrelated newsletter matched: handled=%v rep=%+v calls=%d", handled, rep, eval.calls)
	}

	// 7. Re-seeing an already-recorded reply returns handled=true without calling Jev again.
	handled, _, err = svc.HandleIncoming(context.Background(), ReplyInput{
		MessageID:    "<shock-1@shockhosting.com>",
		From:         "Shock Hosting Abuse <abuse@shockhosting.com>",
		SenderEmail:  "abuse@shockhosting.com",
		SenderDomain: "shockhosting.com",
		Subject:      "[Ticket ID: 708487] [Abuse Report] Unsolicited bulk email from mostbau.com",
		BodySnippet:  "The reported server has been suspended.",
	})
	if err != nil || !handled || eval.calls != callsBefore {
		t.Fatalf("duplicate reply should short-circuit: handled=%v calls=%d err=%v", handled, eval.calls, err)
	}

	bans, err := store.CountAbuseBans()
	if err != nil || bans != 2 {
		t.Fatalf("expected 2 confirmed bans, got %d (err=%v)", bans, err)
	}
	if len(banCallbacks) != 2 || banCallbacks[0] != 1 || banCallbacks[1] != 2 {
		t.Fatalf("unexpected ban callbacks: %v", banCallbacks)
	}
}
