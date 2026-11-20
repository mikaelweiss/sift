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
	"github.com/mikaelweiss/eclean/server/internal/abuse"
	"github.com/mikaelweiss/eclean/server/internal/classifier"
	"github.com/mikaelweiss/eclean/server/internal/db"
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

	trashMailbox := discoverTrashMailbox(c)
	mbox, err := c.Select("INBOX", nil).Wait()
	if err != nil {
		return fmt.Errorf("select INBOX: %w", err)
	}
	w.setStatus(true, "")

	if err := w.processNewMessages(ctx, c, mbox.UIDValidity, trashMailbox); err != nil {
		return err
	}

	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}

		idleCmd, err := c.Idle()
		if err != nil {
			return fmt.Errorf("start IDLE: %w", err)
		}

		refreshTimer := time.NewTimer(20 * time.Minute)
		shouldReload := false
		shouldProcess := false

		select {
		case <-ctx.Done():
			refreshTimer.Stop()
			_ = idleCmd.Close()
			_ = idleCmd.Wait()
			return ctx.Err()
		case <-w.reloadCh:
			shouldReload = true
		case <-newMailCh:
			shouldProcess = true
		case <-refreshTimer.C:
			shouldProcess = true
		case <-c.Closed():
			refreshTimer.Stop()
			return errors.New("imap connection closed by server")
		}
		refreshTimer.Stop()

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
		if shouldProcess {
			if err := w.processNewMessages(ctx, c, mbox.UIDValidity, trashMailbox); err != nil {
				return err
			}
		}
	}
}

func (w *Watcher) processNewMessages(ctx context.Context, c *imapclient.Client, uidValidity uint32, trashMailbox string) error {
	storedValidity, lastUID, err := w.store.GetIMAPCursor()
	if err != nil {
		return err
	}

	if storedValidity == 0 || storedValidity != uidValidity {
		// On fresh start or UIDVALIDITY reset, anchor cursor to current highest UID so only newly arriving mail is filtered in real time.
		allData, err := c.UIDSearch(&goimap.SearchCriteria{}, nil).Wait()
		if err != nil {
			return fmt.Errorf("initial UID search: %w", err)
		}
		uids := allData.AllUIDs()
		var maxUID uint32
		for _, u := range uids {
			if uint32(u) > maxUID {
				maxUID = uint32(u)
			}
		}
		return w.store.SetIMAPCursor(uidValidity, maxUID)
	}

	var uidSet goimap.UIDSet
	uidSet.AddRange(goimap.UID(lastUID+1), 0)
	searchData, err := c.UIDSearch(&goimap.SearchCriteria{UID: []goimap.UIDSet{uidSet}}, nil).Wait()
	if err != nil {
		return fmt.Errorf("search new UIDs: %w", err)
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

	bodySection := &goimap.FetchItemBodySection{Peek: true}
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
		return fmt.Errorf("fetch new messages: %w", err)
	}

	maxSeen := lastUID
	for _, msg := range msgs {
		uid := uint32(msg.UID)
		if uid > maxSeen {
			maxSeen = uid
		}
		if exists, _ := w.store.HasEmailEvent(uidValidity, uid); exists {
			continue
		}
		raw := msg.FindBodySection(bodySection)
		input := ParseRawMessage(uidValidity, uid, msg.InternalDate, raw)

		decision, err := w.classifier.Evaluate(ctx, input)
		if err != nil {
			log.Printf("classify UID %d failed: %v", uid, err)
			continue
		}

		actionTaken := decision.Action
		if decision.Action == "trash" || decision.Action == "delete" {
			if actErr := applySpamAction(c, msg.UID, decision.Action, trashMailbox); actErr != nil {
				log.Printf("apply %s to UID %d failed: %v", decision.Action, uid, actErr)
				actionTaken = "error"
			}
		}

		ev := db.EmailEvent{
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

		if (actionTaken == "trash" || actionTaken == "delete") && w.abuseSvc != nil {
			_ = w.abuseSvc.Consider(ctx, abuse.Candidate{
				SenderEmail:  input.SenderEmail,
				SenderDomain: input.SenderDomain,
				Subject:      input.Subject,
				RawHeaders:   input.RawHeaders,
				CategoryID:   decision.CategoryID,
				Confidence:   decision.Confidence,
				EmailDate:    input.EmailDate,
			})
		}
	}

	return w.store.SetIMAPCursor(uidValidity, maxSeen)
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
	// iCloud requires re-querying CAPABILITY after login so IDLE is advertised cleanly.
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

func discoverTrashMailbox(c *imapclient.Client) string {
	mailboxes, err := c.List("", "*", nil).Collect()
	if err == nil {
		for _, m := range mailboxes {
			for _, attr := range m.Attrs {
				if attr == goimap.MailboxAttrTrash {
					return m.Mailbox
				}
			}
		}
		for _, m := range mailboxes {
			lower := strings.ToLower(m.Mailbox)
			if lower == "deleted messages" || lower == "trash" {
				return m.Mailbox
			}
		}
	}
	return "Deleted Messages"
}

func applySpamAction(c *imapclient.Client, uid goimap.UID, action, trashMailbox string) error {
	var uidSet goimap.UIDSet
	uidSet.AddNum(uid)

	if action == "trash" {
		if _, err := c.Move(uidSet, trashMailbox).Wait(); err == nil {
			return nil
		}
		if _, err := c.Copy(uidSet, trashMailbox).Wait(); err != nil {
			return fmt.Errorf("copy to %s: %w", trashMailbox, err)
		}
	}

	storeCmd := c.Store(uidSet, &goimap.StoreFlags{
		Op:     goimap.StoreFlagsAdd,
		Silent: true,
		Flags:  []goimap.Flag{goimap.FlagDeleted},
	}, nil)
	if err := storeCmd.Close(); err != nil {
		return fmt.Errorf("mark deleted: %w", err)
	}
	if err := c.UIDExpunge(uidSet).Close(); err != nil {
		if expErr := c.Expunge().Close(); expErr != nil {
			return fmt.Errorf("expunge: %w", expErr)
		}
	}
	return nil
}
