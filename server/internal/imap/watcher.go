package imap

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"time"

	goimap "github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"
	"github.com/mikaelweiss/sift/server/internal/abuse"
	"github.com/mikaelweiss/sift/server/internal/classifier"
	"github.com/mikaelweiss/sift/server/internal/db"
)

type StatusSnapshot struct {
	Connected bool
	LastError string
}

type Watcher struct {
	store      *db.Store
	classifier *classifier.Engine
	abuseSvc   *abuse.Service

	mu        sync.RWMutex
	connected bool
	lastError string
	reloadCh  chan struct{}

	OnEventProcessed func(ev db.EmailEvent)
	OnStatusChanged  func(StatusSnapshot)
}

func NewWatcher(store *db.Store, engine *classifier.Engine, abuseSvc *abuse.Service) *Watcher {
	return &Watcher{
		store:      store,
		classifier: engine,
		abuseSvc:   abuseSvc,
		reloadCh:   make(chan struct{}, 1),
	}
}

func (w *Watcher) Status() StatusSnapshot {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return StatusSnapshot{Connected: w.connected, LastError: w.lastError}
}

func (w *Watcher) TriggerReload() {
	select {
	case w.reloadCh <- struct{}{}:
	default:
	}
}

func (w *Watcher) setStatus(connected bool, errMsg string) {
	w.mu.Lock()
	changed := w.connected != connected || w.lastError != errMsg
	w.connected = connected
	w.lastError = errMsg
	w.mu.Unlock()
	if changed && w.OnStatusChanged != nil {
		w.OnStatusChanged(StatusSnapshot{Connected: connected, LastError: errMsg})
	}
}

func (w *Watcher) Run(ctx context.Context) {
	backoff := 2 * time.Second
	for {
		if ctx.Err() != nil {
			w.setStatus(false, "")
			return
		}

		cfg, err := w.store.GetSettings()
		if err != nil {
			w.setStatus(false, err.Error())
		} else if cfg.IMAPUsername == "" || cfg.IMAPPassword == "" {
			w.setStatus(false, "iCloud Mail credentials not configured")
			select {
			case <-ctx.Done():
				return
			case <-w.reloadCh:
				continue
			case <-time.After(15 * time.Second):
				continue
			}
		} else {
			runErr := w.runSession(ctx, cfg)
			if runErr == nil || errors.Is(runErr, context.Canceled) {
				backoff = 2 * time.Second
				continue
			}
			w.setStatus(false, runErr.Error())
			log.Printf("imap watcher disconnected: %v", runErr)
		}

		select {
		case <-ctx.Done():
			return
		case <-w.reloadCh:
			backoff = 2 * time.Second
		case <-time.After(backoff):
			if backoff < 60*time.Second {
				backoff *= 2
			}
		}
	}
}

func (w *Watcher) runSession(ctx context.Context, cfg db.AppSettings) error {
	newMailCh := make(chan struct{}, 1)
	opts := &imapclient.Options{
		TLSConfig: &tls.Config{ServerName: cfg.IMAPHost, MinVersion: tls.VersionTLS12},
		UnilateralDataHandler: &imapclient.UnilateralDataHandler{
			Mailbox: func(data *imapclient.UnilateralDataMailbox) {
				if data.NumMessages != nil {
					select {
					case newMailCh <- struct{}{}:
					default:
					}
				}
			},
		},
	}

	c, err := dialAndLogin(cfg.IMAPHost, cfg.IMAPPort, cfg.IMAPUsername, cfg.IMAPPassword, opts)
	if err != nil {
		return err
	}
	defer c.Close()

	boxes := discoverSpamMailboxes(c)
	watchMailboxes := DiscoverMailboxes(c, false)
	w.setStatus(true, "")

	if err := w.sweepMailboxes(ctx, c, watchMailboxes, boxes); err != nil {
		return err
	}
	go MaybeBackfillAbuseReplies(ctx, w.store, w.abuseSvc)

	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}

		// Keep INBOX selected for real-time IDLE push, and sweep Junk and custom folders every 2 minutes or on wakeup.
		if _, err := c.Select("INBOX", nil).Wait(); err != nil {
			return fmt.Errorf("select INBOX: %w", err)
		}

		idleCmd, err := c.Idle()
		if err != nil {
			return fmt.Errorf("start IDLE: %w", err)
		}

		sweepTimer := time.NewTimer(2 * time.Minute)
		shouldReload := false
		shouldSweep := false

		select {
		case <-ctx.Done():
			sweepTimer.Stop()
			_ = idleCmd.Close()
			_ = idleCmd.Wait()
			return ctx.Err()
		case <-w.reloadCh:
			shouldReload = true
		case <-newMailCh:
			shouldSweep = true
		case <-sweepTimer.C:
			shouldSweep = true
		case <-c.Closed():
			sweepTimer.Stop()
			return errors.New("imap connection closed by server")
		}
		sweepTimer.Stop()

		if err := idleCmd.Close(); err != nil {
			return fmt.Errorf("close IDLE: %w", err)
		}
		if err := idleCmd.Wait(); err != nil {
			return fmt.Errorf("wait IDLE: %w", err)
		}
		if shouldReload {
			_ = c.Logout().Wait()
			return nil
		}
		if shouldSweep {
			watchMailboxes = DiscoverMailboxes(c, false)
			if err := w.sweepMailboxes(ctx, c, watchMailboxes, boxes); err != nil {
				return err
			}
		}
	}
}

func (w *Watcher) sweepMailboxes(ctx context.Context, c *imapclient.Client, mailboxes []string, boxes spamMailboxes) error {
	for _, mailbox := range mailboxes {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		mbox, err := c.Select(mailbox, nil).Wait()
		if err != nil {
			log.Printf("select %q skipped: %v", mailbox, err)
			continue
		}
		if err := w.processNewMessages(ctx, c, mailbox, mbox.UIDValidity, boxes); err != nil {
			return err
		}
	}
	return nil
}

func (w *Watcher) processNewMessages(ctx context.Context, c *imapclient.Client, mailbox string, uidValidity uint32, boxes spamMailboxes) error {
	storedValidity, lastUID, err := w.store.GetMailboxCursor(mailbox)
	if err != nil {
		return err
	}

	if storedValidity == 0 || storedValidity != uidValidity {
		// Anchor new mailboxes to their current max UID so only newly arriving mail is filtered in real time.
		allData, err := c.UIDSearch(&goimap.SearchCriteria{}, nil).Wait()
		if err != nil {
			return fmt.Errorf("initial UID search in %s: %w", mailbox, err)
		}
		var maxUID uint32
		for _, u := range allData.AllUIDs() {
			if uint32(u) > maxUID {
				maxUID = uint32(u)
			}
		}
		return w.store.SetMailboxCursor(mailbox, uidValidity, maxUID)
	}

	var uidSet goimap.UIDSet
	uidSet.AddRange(goimap.UID(lastUID+1), 0)
	searchData, err := c.UIDSearch(&goimap.SearchCriteria{UID: []goimap.UIDSet{uidSet}}, nil).Wait()
	if err != nil {
		return fmt.Errorf("search new UIDs in %s: %w", mailbox, err)
	}

	var newUIDs []goimap.UID
	for _, u := range searchData.AllUIDs() {
		if uint32(u) > lastUID {
			newUIDs = append(newUIDs, u)
		}
	}
	if len(newUIDs) == 0 {
		return nil
	}

	bodySection := &goimap.FetchItemBodySection{
		Peek:    true,
		Partial: &goimap.SectionPartial{Offset: 0, Size: maxFetchBytes},
	}
	var fetchSet goimap.UIDSet
	for _, u := range newUIDs {
		fetchSet.AddNum(u)
	}
	msgs, err := c.Fetch(fetchSet, &goimap.FetchOptions{
		UID:          true,
		InternalDate: true,
		BodySection:  []*goimap.FetchItemBodySection{bodySection},
	}).Collect()
	if err != nil {
		return fmt.Errorf("fetch new messages in %s: %w", mailbox, err)
	}

	maxSeen := lastUID
	for _, msg := range msgs {
		uid := uint32(msg.UID)
		if uid > maxSeen {
			maxSeen = uid
		}
		if exists, _ := w.store.HasEmailEvent(mailbox, uidValidity, uid); exists {
			continue
		}
		raw := extractBodyBytes(msg, bodySection)
		input := ParseRawMessage(uidValidity, uid, msg.InternalDate, raw)

		if w.abuseSvc != nil {
			handled, _, repErr := w.abuseSvc.HandleIncoming(ctx, replyInputFromEmail(input))
			if repErr != nil {
				log.Printf("abuse reply check %s UID %d failed: %v", mailbox, uid, repErr)
			} else if handled {
				actionTaken := "abuse_reply"
				if actErr := archiveMessages(c, []goimap.UID{msg.UID}, mailbox, boxes); actErr != nil {
					log.Printf("archive abuse reply %s UID %d failed: %v", mailbox, uid, actErr)
					actionTaken = "error"
				}
				_ = w.store.RecordEmailEvent(db.EmailEvent{
					Mailbox:      mailbox,
					UIDValidity:  uidValidity,
					UID:          uid,
					MessageID:    input.MessageID,
					Sender:       input.SenderEmail,
					SenderDomain: input.SenderDomain,
					Subject:      input.Subject,
					EmailDate:    input.EmailDate.UTC().Format(time.RFC3339),
					Action:       actionTaken,
					Source:       "realtime",
				})
				continue
			}
		}

		decision, err := w.classifier.Evaluate(ctx, input)
		if err != nil {
			log.Printf("classify %s UID %d failed: %v", mailbox, uid, err)
			continue
		}

		actionTaken := decision.Action
		if decision.Action == "junk" || decision.Action == "delete" {
			if actErr := applySpamAction(c, []goimap.UID{msg.UID}, decision.Action, mailbox, boxes); actErr != nil {
				log.Printf("apply %s to %s UID %d failed: %v", decision.Action, mailbox, uid, actErr)
				actionTaken = "error"
			}
		}

		ev := db.EmailEvent{
			Mailbox:      mailbox,
			UIDValidity:  uidValidity,
			UID:          uid,
			MessageID:    input.MessageID,
			Sender:       input.SenderEmail,
			SenderDomain: input.SenderDomain,
			Subject:      input.Subject,
			EmailDate:    input.EmailDate.UTC().Format(time.RFC3339),
			CategoryID:   decision.CategoryID,
			Confidence:   decision.Confidence,
			Action:       actionTaken,
			Source:       "realtime",
		}
		if err := w.store.RecordEmailEvent(ev); err == nil && w.OnEventProcessed != nil {
			w.OnEventProcessed(ev)
		}

		if sighting, ok := mailingListSighting(input, decision); ok {
			_ = w.store.RecordMailingListSightings([]db.MailingListSighting{sighting})
		}
		if cand, ok := abuseCandidate(input, decision.CategoryID, decision.Confidence, actionTaken); ok && w.abuseSvc != nil {
			_ = w.abuseSvc.Consider(ctx, cand)
		}
	}

	return w.store.SetMailboxCursor(mailbox, uidValidity, maxSeen)
}

func dialAndLogin(host string, port int, username, password string, opts *imapclient.Options) (*imapclient.Client, error) {
	if host == "" {
		host = "imap.mail.me.com"
	}
	if port == 0 {
		port = 993
	}
	if opts == nil {
		opts = &imapclient.Options{
			TLSConfig: &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12},
		}
	}
	addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	c, err := imapclient.DialTLS(addr, opts)
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", addr, err)
	}
	if err := c.Login(username, password).Wait(); err != nil {
		_ = c.Close()
		return nil, fmt.Errorf("imap login: %w", err)
	}
	_, _ = c.Capability().Wait()
	return c, nil
}

func TestConnection(host string, port int, username, password string) error {
	if strings.TrimSpace(username) == "" || strings.TrimSpace(password) == "" {
		return errors.New("username and app-specific password are required")
	}
	c, err := dialAndLogin(host, port, username, password, nil)
	if err != nil {
		return err
	}
	defer c.Close()
	if _, err := c.Select("INBOX", &goimap.SelectOptions{ReadOnly: true}).Wait(); err != nil {
		return fmt.Errorf("select INBOX: %w", err)
	}
	_ = c.Logout().Wait()
	return nil
}

func extractBodyBytes(msg *imapclient.FetchMessageBuffer, section *goimap.FetchItemBodySection) []byte {
	if raw := msg.FindBodySection(section); len(raw) > 0 {
		return raw
	}
	if len(msg.BodySection) > 0 {
		return msg.BodySection[0].Bytes
	}
	return nil
}
