package imap

import (
	"sort"
	"strings"

	goimap "github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"
)

func DiscoverMailboxes(c *imapclient.Client, includeHistoricalFolders bool) []string {
	list, err := c.List("", "*", nil).Collect()
	if err != nil || len(list) == 0 {
		return []string{"INBOX"}
	}
	return FilterScannableMailboxes(list, includeHistoricalFolders)
}

func FilterScannableMailboxes(list []*goimap.ListData, includeHistoricalFolders bool) []string {
	var inbox []string
	var junk []string
	var archive []string
	var trash []string
	var others []string

	for _, m := range list {
		if shouldSkipMailbox(m, includeHistoricalFolders) {
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
		case hasAttr(m.Attrs, goimap.MailboxAttrTrash) || lower == "deleted messages" || lower == "trash":
			trash = append(trash, name)
		default:
			others = append(others, name)
		}
	}

	sort.Strings(others)
	out := make([]string, 0, len(inbox)+len(junk)+len(archive)+len(trash)+len(others))
	out = append(out, inbox...)
	out = append(out, junk...)
	out = append(out, archive...)
	out = append(out, trash...)
	out = append(out, others...)
	if len(out) == 0 {
		return []string{"INBOX"}
	}
	return out
}

func shouldSkipMailbox(m *goimap.ListData, includeHistoricalFolders bool) bool {
	for _, attr := range m.Attrs {
		switch attr {
		case goimap.MailboxAttrNoSelect,
			goimap.MailboxAttrNonExistent,
			goimap.MailboxAttrSent,
			goimap.MailboxAttrDrafts,
			goimap.MailboxAttrAll:
			return true
		case goimap.MailboxAttrArchive, goimap.MailboxAttrTrash:
			if !includeHistoricalFolders {
				return true
			}
		}
	}

	lower := strings.ToLower(strings.TrimSpace(m.Mailbox))
	switch lower {
	case "sent messages", "sent", "drafts", "notes", "outbox", "recovered messages":
		return true
	case "archive", "deleted messages", "trash":
		return !includeHistoricalFolders
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
