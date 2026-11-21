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
	wantHist := []string{"INBOX", "Junk", "Archive", "Receipts", "Work"}
	if !reflect.DeepEqual(hist, wantHist) {
		t.Fatalf("historical mailboxes mismatch: got %v want %v", hist, wantHist)
	}

	rt := FilterScannableMailboxes(list, false)
	wantRT := []string{"INBOX", "Junk", "Receipts", "Work"}
	if !reflect.DeepEqual(rt, wantRT) {
		t.Fatalf("realtime mailboxes mismatch: got %v want %v", rt, wantRT)
	}
}
