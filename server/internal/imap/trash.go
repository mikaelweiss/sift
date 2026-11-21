package imap

import (
	"errors"
	"fmt"
	"sort"

	goimap "github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"
	"github.com/mikaelweiss/eclean/server/internal/db"
)

type TrashItem struct {
	UID        uint32  `json:"uid"`
	Sender     string  `json:"sender"`
	Subject    string  `json:"subject"`
	EmailDate  string  `json:"email_date"`
	CategoryID string  `json:"category_id"`
	Confidence float64 `json:"confidence"`
}

type TrashListing struct {
	Mailbox     string      `json:"mailbox"`
	UIDValidity uint32      `json:"uid_validity"`
	Items       []TrashItem `json:"items"`
}

// trashSession holds the Trash mailbox selected, paired with the Message-IDs EClean trashed.
// Matching by Message-ID keeps mail the user trashed themselves out of reach.
type trashSession struct {
	c           *imapclient.Client
	mailbox     string
	uidValidity uint32
	numMessages uint32
	trashed     map[string]db.EmailEvent
}

func openTrash(store *db.Store, readOnly bool) (*trashSession, error) {
	cfg, err := store.GetSettings()
	if err != nil {
		return nil, err
	}
	trashed, err := store.ListTrashedEvents()
	if err != nil {
		return nil, err
	}
	c, err := dialScanClient(cfg.IMAPHost, cfg.IMAPPort, cfg.IMAPUsername, cfg.IMAPPassword, nil)
	if err != nil {
		return nil, err
	}
	mailbox := discoverTrashMailbox(c)
	data, err := c.Select(mailbox, &goimap.SelectOptions{ReadOnly: readOnly}).Wait()
	if err != nil {
		_ = c.Close()
		return nil, fmt.Errorf("select %s: %w", mailbox, err)
	}
	return &trashSession{c: c, mailbox: mailbox, uidValidity: data.UIDValidity, numMessages: data.NumMessages, trashed: trashed}, nil
}

func (t *trashSession) close() {
	_ = t.c.Logout().Wait()
	_ = t.c.Close()
}

// ecleanMessages returns the messages in fetchSet that EClean trashed, keyed by UID.
func (t *trashSession) ecleanMessages(fetchSet goimap.NumSet) (map[uint32]db.EmailEvent, error) {
	msgs, err := t.c.Fetch(fetchSet, &goimap.FetchOptions{UID: true, Envelope: true}).Collect()
	if err != nil {
		return nil, fmt.Errorf("fetch %s: %w", t.mailbox, err)
	}
	out := map[uint32]db.EmailEvent{}
	for _, m := range msgs {
		if m.Envelope == nil {
			continue
		}
		if ev, ok := t.trashed[db.NormalizeMessageID(m.Envelope.MessageID)]; ok {
			out[uint32(m.UID)] = ev
		}
	}
	return out, nil
}

func ListTrash(store *db.Store) (TrashListing, error) {
	t, err := openTrash(store, true)
	if err != nil {
		return TrashListing{}, err
	}
	defer t.close()

	listing := TrashListing{Mailbox: t.mailbox, UIDValidity: t.uidValidity, Items: []TrashItem{}}
	if t.numMessages == 0 || len(t.trashed) == 0 {
		return listing, nil
	}
	var all goimap.SeqSet
	all.AddRange(1, 0)
	found, err := t.ecleanMessages(all)
	if err != nil {
		return TrashListing{}, err
	}
	for uid, ev := range found {
		listing.Items = append(listing.Items, TrashItem{
			UID:        uid,
			Sender:     ev.Sender,
			Subject:    ev.Subject,
			EmailDate:  ev.EmailDate,
			CategoryID: ev.CategoryID,
			Confidence: ev.Confidence,
		})
	}
	sort.Slice(listing.Items, func(i, j int) bool {
		a, b := listing.Items[i], listing.Items[j]
		if a.Confidence != b.Confidence {
			return a.Confidence > b.Confidence
		}
		return a.EmailDate > b.EmailDate
	})
	return listing, nil
}

// DeleteFromTrash permanently removes the given Trash UIDs that EClean put there and returns how many it removed.
func DeleteFromTrash(store *db.Store, uidValidity uint32, uids []uint32) (int, error) {
	if len(uids) == 0 {
		return 0, nil
	}
	t, err := openTrash(store, false)
	if err != nil {
		return 0, err
	}
	defer t.close()
	if t.uidValidity != uidValidity {
		return 0, errors.New("the Trash mailbox changed since it was listed, reload and try again")
	}

	var requested goimap.UIDSet
	for _, u := range uids {
		requested.AddNum(goimap.UID(u))
	}
	found, err := t.ecleanMessages(requested)
	if err != nil {
		return 0, err
	}
	if len(found) == 0 {
		return 0, nil
	}

	var target goimap.UIDSet
	var messageIDs []string
	for uid, ev := range found {
		target.AddNum(goimap.UID(uid))
		messageIDs = append(messageIDs, ev.MessageID)
	}
	if err := t.c.Store(target, &goimap.StoreFlags{Op: goimap.StoreFlagsAdd, Silent: true, Flags: []goimap.Flag{goimap.FlagDeleted}}, nil).Close(); err != nil {
		return 0, fmt.Errorf("mark deleted: %w", err)
	}
	// A plain EXPUNGE would also remove anything else flagged \Deleted, so there is no fallback.
	if err := t.c.UIDExpunge(target).Close(); err != nil {
		return 0, fmt.Errorf("expunge: %w", err)
	}
	if err := store.MarkTrashedEventsDeleted(messageIDs); err != nil {
		return 0, err
	}
	return len(found), nil
}
