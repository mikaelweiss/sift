package imap

import (
	"sort"
	"strings"

	goimap "github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"
)

func DiscoverMailboxes(c *imapclient.Client, includeArchive bool) []string {
	list, err := c.List("", "*", nil).Collect()
	if err != nil || len(list) == 0 {
		return []string{"INBOX"}
	}
	return FilterScannableMailboxes(list, includeArchive)
}

func FilterScannableMailboxes(list []*goimap.ListData, includeArchive bool) []string {
	var inbox []string
	var junk []string
	var archive []string
	var others []string

	for _, m := range list {
		if shouldSkipMailbox(m, includeArchive) {
			continue
		}
		name := m.Mailbox
		lower := strings.ToLower(name)
		switch {
		case lower == "inbox":
			inbox = append(inbox, name)
		case hasAttr(m.Attrs, goimap.MailboxAttrJunk) || lower == "junk" || lower == "spam":
			junk = append(junk, name)
		case hasAttr(m.Attrs, goimap.MailboxAttrArchive) || lower == "archive":
			archive = append(archive, name)
		default:
			others = append(others, name)
		}
	}

	sort.Strings(others)
	out := make([]string, 0, len(inbox)+len(junk)+len(archive)+len(others))
	out = append(out, inbox...)
	out = append(out, junk...)
	out = append(out, archive...)
	out = append(out, others...)
	if len(out) == 0 {
		return []string{"INBOX"}
	}
	return out
}

func shouldSkipMailbox(m *goimap.ListData, includeArchive bool) bool {
	for _, attr := range m.Attrs {
		switch attr {
		case goimap.MailboxAttrNoSelect,
			goimap.MailboxAttrNonExistent,
			goimap.MailboxAttrTrash,
			goimap.MailboxAttrSent,
			goimap.MailboxAttrDrafts,
			goimap.MailboxAttrAll:
			return true
		case goimap.MailboxAttrArchive:
			if !includeArchive {
				return true
			}
		}
	}

	lower := strings.ToLower(strings.TrimSpace(m.Mailbox))
	switch lower {
	case "deleted messages", "trash", "sent messages", "sent", "drafts", "notes", "outbox", "recovered messages":
		return true
	case "archive":
		return !includeArchive
	}
	return false
}

func hasAttr(attrs []goimap.MailboxAttr, target goimap.MailboxAttr) bool {
	for _, a := range attrs {
		if a == target {
			return true
		}
	}
	return false
}
