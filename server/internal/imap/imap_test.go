package imap

import (
	"reflect"
	"strings"
	"testing"
	"time"

	goimap "github.com/emersion/go-imap/v2"
)

func TestParseRawMessageMultipartHTMLAndHeaders(t *testing.T) {
	raw := strings.Join([]string{
		"From: \"Big Promo\" <deals@promo.example.com>",
		"Reply-To: reply@promo.example.com",
		"To: user@icloud.com",
		"Subject: =?UTF-8?Q?50%25_Off_Today?=",
		"Date: Fri, 20 Nov 2026 14:00:00 +0000",
		"Message-ID: <msg-1@promo.example.com>",
		"Authentication-Results: mx.icloud.com; spf=pass; dkim=fail",
		"MIME-Version: 1.0",
		"Content-Type: multipart/alternative; boundary=BOUND",
		"",
		"--BOUND",
		"Content-Type: text/html; charset=UTF-8",
		"",
		"<html><body><p>Click <a href=\"https://track.spam.test/go\">here</a> now!</p></body></html>",
		"--BOUND--",
	}, "\r\n")

	in := ParseRawMessage(100, 7, time.Time{}, []byte(raw))
	if in.SenderEmail != "deals@promo.example.com" || in.SenderDomain != "promo.example.com" {
		t.Fatalf("unexpected sender: %s / %s", in.SenderEmail, in.SenderDomain)
	}
	if !strings.Contains(in.BodySnippet, "Click here now!") {
		t.Fatalf("expected stripped HTML text, got %q", in.BodySnippet)
	}
	if len(in.LinkDomains) != 1 || in.LinkDomains[0] != "track.spam.test" {
		t.Fatalf("unexpected link domains: %+v", in.LinkDomains)
	}
	if !strings.Contains(in.AuthResults, "dkim=fail") {
		t.Fatalf("missing auth results: %q", in.AuthResults)
	}
	if in.EmailDate.Year() != 2026 {
		t.Fatalf("unexpected email date: %v", in.EmailDate)
	}
}

func TestParseRawMessageTrustsOnlyTheFirstICloudDMARCVerdict(t *testing.T) {
	msg := func(authResults ...string) []byte {
		var lines []string
		for _, ar := range authResults {
			lines = append(lines, "Authentication-Results: "+ar)
		}
		lines = append(lines,
			"From: Apple <no_reply@email.apple.com>",
			"List-Unsubscribe: <mailto:unsub@email.apple.com>, <https://email.apple.com/unsub?id=1>",
			"List-Unsubscribe-Post: List-Unsubscribe=One-Click",
			"Subject: Hi", "", "Body")
		return []byte(strings.Join(lines, "\r\n"))
	}

	pass := ParseRawMessage(1, 1, time.Time{}, msg("dmarc.icloud.com; dmarc=pass header.from=email.apple.com"))
	if !pass.DMARCPass {
		t.Fatal("iCloud DMARC pass not recognized")
	}
	if pass.UnsubscribeURL != "https://email.apple.com/unsub?id=1" {
		t.Fatalf("unsubscribe URL %q", pass.UnsubscribeURL)
	}

	forged := ParseRawMessage(1, 1, time.Time{}, msg(
		"dmarc.icloud.com; dmarc=fail header.from=email.apple.com",
		"dmarc.icloud.com; dmarc=pass header.from=email.apple.com",
	))
	if forged.DMARCPass {
		t.Fatal("a later forged pass overrode iCloud's fail")
	}

	foreign := ParseRawMessage(1, 1, time.Time{}, msg("mx.evil.test; dmarc=pass header.from=email.apple.com"))
	if foreign.DMARCPass {
		t.Fatal("trusted a verdict from a non-iCloud authserv-id")
	}

	other := ParseRawMessage(1, 1, time.Time{}, msg("dmarc.icloud.com; dmarc=pass header.from=evil.test"))
	if other.DMARCPass {
		t.Fatal("DMARC pass for another domain counted for the sender")
	}
}

func TestBuildSearchCriteria(t *testing.T) {
	now := time.Date(2026, 11, 20, 0, 0, 0, 0, time.UTC)
	c30 := buildSearchCriteria("30d", now)
	if c30.Since.IsZero() || now.Sub(c30.Since) != 30*24*time.Hour {
		t.Fatalf("expected 30d criteria, got %+v", c30)
	}
	cAll := buildSearchCriteria("all", now)
	if !cAll.Since.IsZero() {
		t.Fatalf("expected empty Since for all")
	}
}

func TestFilterScannableMailboxes(t *testing.T) {
	list := []*goimap.ListData{
		{Mailbox: "INBOX"},
		{Mailbox: "Junk", Attrs: []goimap.MailboxAttr{goimap.MailboxAttrJunk}},
		{Mailbox: "Archive", Attrs: []goimap.MailboxAttr{goimap.MailboxAttrArchive}},
		{Mailbox: "Deleted Messages", Attrs: []goimap.MailboxAttr{goimap.MailboxAttrTrash}},
		{Mailbox: "Sent Messages", Attrs: []goimap.MailboxAttr{goimap.MailboxAttrSent}},
		{Mailbox: "Drafts", Attrs: []goimap.MailboxAttr{goimap.MailboxAttrDrafts}},
		{Mailbox: "Notes"},
		{Mailbox: "Receipts"},
		{Mailbox: "Work"},
		{Mailbox: "FolderContainer", Attrs: []goimap.MailboxAttr{goimap.MailboxAttrNoSelect}},
	}

	hist := FilterScannableMailboxes(list, true)
	wantHist := []string{"INBOX", "Junk", "Archive", "Deleted Messages", "Receipts", "Work"}
	if !reflect.DeepEqual(hist, wantHist) {
		t.Fatalf("historical mailboxes mismatch: got %v want %v", hist, wantHist)
	}

	rt := FilterScannableMailboxes(list, false)
	wantRT := []string{"INBOX", "Junk", "Receipts", "Work"}
	if !reflect.DeepEqual(rt, wantRT) {
		t.Fatalf("realtime mailboxes mismatch: got %v want %v", rt, wantRT)
	}
}
