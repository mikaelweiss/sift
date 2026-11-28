package imap

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"net/mail"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	goimap "github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"
	"github.com/mikaelweiss/sift/server/internal/abuse"
	"github.com/mikaelweiss/sift/server/internal/classifier"
	"github.com/mikaelweiss/sift/server/internal/db"
)

const abuseBackfillSettingKey = "abuse_replies_backfilled_v1"

var (
	abuseSyncMu            sync.Mutex
	abuseBackfillInRunning atomic.Bool
)

type AbuseSyncResult struct {
	Processed   int `json:"processed"`
	Archived    int `json:"archived"`
	BansFound   int `json:"bans_found"`
	BannedCount int `json:"banned_count"`
}

func replyInputFromEmail(in classifier.EmailInput) abuse.ReplyInput {
	return abuse.ReplyInput{
		MessageID:     in.MessageID,
		InReplyTo:     in.InReplyTo,
		References:    in.References,
		From:          in.From,
		SenderEmail:   in.SenderEmail,
		SenderDomain:  in.SenderDomain,
		Subject:       in.Subject,
		BodySnippet:   in.BodySnippet,
		AutoSubmitted: in.AutoSubmitted,
		RawHeaders:    in.RawHeaders,
		RawMessage:    in.RawMessage,
		EmailDate:     in.EmailDate,
	}
}

// MaybeBackfillAbuseReplies runs a one-time scan over recent INBOX and Archive mail so existing
// ban confirmations are counted and leftover abuse replies are archived after upgrading.
func MaybeBackfillAbuseReplies(ctx context.Context, store *db.Store, abuseSvc *abuse.Service) {
	if store == nil || abuseSvc == nil {
		return
	}
	if !abuseBackfillInRunning.CompareAndSwap(false, true) {
		return
	}
	defer abuseBackfillInRunning.Store(false)

	if done, _, err := store.GetRawSetting(abuseBackfillSettingKey); err == nil && done == "true" {
		return
	}
	cfg, err := store.GetSettings()
	if err != nil || cfg.IMAPUsername == "" || cfg.IMAPPassword == "" || cfg.AIAPIKey == "" {
		return
	}
	res, err := SyncAbuseReplies(ctx, store, abuseSvc, 90)
	if err != nil {
		log.Printf("abuse reply backfill failed: %v", err)
		return
	}
	_ = store.SetRawSetting(abuseBackfillSettingKey, "true", false)
	log.Printf("abuse reply backfill finished: processed=%d archived=%d bans_found=%d total_bans=%d",
		res.Processed, res.Archived, res.BansFound, res.BannedCount)
}

// SyncAbuseReplies scans recent INBOX and Archive mail for abuse report replies and bounces,
// records bans and learned form-only desks, and archives any matching messages still in INBOX.
func SyncAbuseReplies(ctx context.Context, store *db.Store, abuseSvc *abuse.Service, days int) (AbuseSyncResult, error) {
	var res AbuseSyncResult
	if store == nil || abuseSvc == nil {
		return res, nil
	}
	if days <= 0 {
		days = 90
	}

	abuseSyncMu.Lock()
	defer abuseSyncMu.Unlock()

	cfg, err := store.GetSettings()
	if err != nil {
		return res, err
	}
	if cfg.IMAPUsername == "" || cfg.IMAPPassword == "" {
		return res, fmt.Errorf("iCloud Mail credentials not configured")
	}

	c, err := dialAndLogin(cfg.IMAPHost, cfg.IMAPPort, cfg.IMAPUsername, cfg.IMAPPassword, nil)
	if err != nil {
		return res, err
	}
	defer c.Close()

	boxes := discoverSpamMailboxes(c)
	mailboxes := []string{"INBOX"}
	if boxes.archive != "" && !strings.EqualFold(boxes.archive, "INBOX") {
		mailboxes = append(mailboxes, boxes.archive)
	}

	since := time.Now().UTC().AddDate(0, 0, -days)
	knownTargets := abuseSvc.KnownTargetRootDomains()

	for _, mailbox := range mailboxes {
		if ctx.Err() != nil {
			return res, ctx.Err()
		}
		mbox, err := c.Select(mailbox, nil).Wait()
		if err != nil {
			log.Printf("abuse sync skip %q: %v", mailbox, err)
			continue
		}
		searchData, err := c.UIDSearch(&goimap.SearchCriteria{Since: since}, nil).Wait()
		if err != nil {
			log.Printf("abuse sync search %q: %v", mailbox, err)
			continue
		}
		allUIDs := searchData.AllUIDs()
		if len(allUIDs) == 0 {
			continue
		}

		candidateUIDs := filterCandidateUIDs(c, allUIDs, knownTargets, cfg.IMAPUsername)
		if len(candidateUIDs) == 0 {
			continue
		}

		var toArchive []goimap.UID
		bodySection := &goimap.FetchItemBodySection{
			Peek:    true,
			Partial: &goimap.SectionPartial{Offset: 0, Size: maxFetchBytes},
		}
		for start := 0; start < len(candidateUIDs); start += 50 {
			if ctx.Err() != nil {
				return res, ctx.Err()
			}
			end := min(start+50, len(candidateUIDs))
			var fetchSet goimap.UIDSet
			for _, u := range candidateUIDs[start:end] {
				fetchSet.AddNum(u)
			}
			msgs, err := c.Fetch(fetchSet, &goimap.FetchOptions{
				UID:          true,
				InternalDate: true,
				BodySection:  []*goimap.FetchItemBodySection{bodySection},
			}).Collect()
			if err != nil {
				log.Printf("abuse sync fetch bodies %q: %v", mailbox, err)
				continue
			}
			for _, msg := range msgs {
				raw := extractBodyBytes(msg, bodySection)
				input := ParseRawMessage(mbox.UIDValidity, uint32(msg.UID), msg.InternalDate, raw)
				handled, reply, hErr := abuseSvc.HandleIncoming(ctx, replyInputFromEmail(input))
				if hErr != nil {
					log.Printf("abuse sync classify %s UID %d: %v", mailbox, msg.UID, hErr)
					continue
				}
				if !handled {
					continue
				}
				res.Processed++
				if reply != nil && reply.Outcome == abuse.OutcomeActionTaken {
					res.BansFound++
				}
				if !strings.EqualFold(mailbox, boxes.archive) {
					toArchive = append(toArchive, msg.UID)
				}
			}
		}

		if len(toArchive) > 0 {
			if err := archiveMessages(c, toArchive, mailbox, boxes); err != nil {
				log.Printf("abuse sync archive %q: %v", mailbox, err)
			} else {
				res.Archived += len(toArchive)
			}
		}
	}

	_ = c.Logout().Wait()
	res.BannedCount, _ = store.CountAbuseBans()
	return res, nil
}

func filterCandidateUIDs(c *imapclient.Client, uids []goimap.UID, knownTargets map[string]struct{}, ownEmail string) []goimap.UID {
	headerSection := &goimap.FetchItemBodySection{
		Peek:         true,
		Specifier:    goimap.PartSpecifierHeader,
		HeaderFields: []string{"From", "Subject", "In-Reply-To", "References", "Content-Type"},
	}
	var out []goimap.UID
	for start := 0; start < len(uids); start += 200 {
		end := min(start+200, len(uids))
		var fetchSet goimap.UIDSet
		for _, u := range uids[start:end] {
			fetchSet.AddNum(u)
		}
		msgs, err := c.Fetch(fetchSet, &goimap.FetchOptions{
			UID:         true,
			BodySection: []*goimap.FetchItemBodySection{headerSection},
		}).Collect()
		if err != nil {
			continue
		}
		for _, msg := range msgs {
			raw := extractBodyBytes(msg, headerSection)
			parsed, err := mail.ReadMessage(bytes.NewReader(append(raw, "\r\n"...)))
			if err != nil {
				continue
			}
			from := decodeHeader(parsed.Header.Get("From"))
			subject := decodeHeader(parsed.Header.Get("Subject"))
			if abuse.IsHeaderCandidate(
				from,
				subject,
				parsed.Header.Get("In-Reply-To"),
				parsed.Header.Get("References"),
				parsed.Header.Get("Content-Type"),
				knownTargets,
				ownEmail,
			) {
				out = append(out, msg.UID)
			}
		}
	}
	return out
}
