package imap

import (
	"net/mail"
	"strings"

	"github.com/mikaelweiss/sift/server/internal/abuse"
	"github.com/mikaelweiss/sift/server/internal/classifier"
	"github.com/mikaelweiss/sift/server/internal/db"
)

func isSpamAction(action string) bool {
	return action == "junk" || action == "delete"
}

// reportable says whether a verdict could become an abuse report, so its message is worth keeping as evidence.
func reportable(in classifier.EmailInput, action string) bool {
	return isSpamAction(action) && wAgeWithin7Days(in.EmailDate) && in.RawMessage != ""
}

func abuseCandidate(in classifier.EmailInput, categoryID string, confidence float64, action string) (abuse.Candidate, bool) {
	if !reportable(in, action) {
		return abuse.Candidate{}, false
	}
	return abuse.Candidate{
		SenderEmail:  in.SenderEmail,
		SenderDomain: in.SenderDomain,
		From:         in.From,
		Subject:      in.Subject,
		RawMessage:   in.RawMessage,
		LinkDomains:  in.LinkDomains,
		CategoryID:   categoryID,
		Confidence:   confidence,
		EmailDate:    in.EmailDate,
	}, true
}

func mailingListSighting(in classifier.EmailInput, dec classifier.Decision) (db.MailingListSighting, bool) {
	if in.UnsubscribeURL == "" || in.SenderEmail == "" || in.EmailDate.IsZero() {
		return db.MailingListSighting{}, false
	}
	name := ""
	if addr, err := mail.ParseAddress(in.From); err == nil {
		name = strings.TrimSpace(addr.Name)
	}
	return db.MailingListSighting{
		Sender:         in.SenderEmail,
		DisplayName:    name,
		SenderDomain:   in.SenderDomain,
		UnsubscribeURL: in.UnsubscribeURL,
		DMARCPass:      in.DMARCPass,
		Flagged:        isSpamAction(dec.Action) && dec.AbuseEligible,
		EmailDate:      in.EmailDate.UTC().Format("2006-01-02T15:04:05Z"),
		Subject:        in.Subject,
	}, true
}
