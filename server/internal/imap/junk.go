package imap

import (
	"errors"
	"fmt"
	"sort"

	goimap "github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"
	"github.com/mikaelweiss/sift/server/internal/db"
)

type JunkItem struct {
	UID        uint32  `json:"uid"`
	Sender     string  `json:"sender"`
	Subject    string  `json:"subject"`
	EmailDate  string  `json:"email_date"`
	CategoryID string  `json:"category_id"`
	Confidence float64 `json:"confidence"`
}

type JunkListing struct {
	Mailbox     string     `json:"mailbox"`
	UIDValidity uint32     `json:"uid_validity"`
	Items       []JunkItem `json:"items"`
}

// junkSession holds the Junk mailbox selected, paired with the Message-IDs Sift moved there.
// Matching by Message-ID keeps mail that landed in Junk some other way out of reach.
type junkSession struct {
	c           *imapclient.Client
	mailbox     string
	uidValidity uint32
	numMessages uint32
	junked      map[string]db.EmailEvent
}

func openJunk(store *db.Store, readOnly bool) (*junkSession, error) {
	cfg, err := store.GetSettings()
	if err != nil {
		return nil, err
	}
	junked, err := store.ListJunkedEvents()
	if err != nil {
		return nil, err
	}
	c, err := dialScanClient(cfg.IMAPHost, cfg.IMAPPort, cfg.IMAPUsername, cfg.IMAPPassword, nil)
	if err != nil {
		return nil, err
	}
	mailbox := discoverSpamMailboxes(c).junk
	data, err := c.Select(mailbox, &goimap.SelectOptions{ReadOnly: readOnly}).Wait()
	if err != nil {
		_ = c.Close()
		return nil, fmt.Errorf("select %s: %w", mailbox, err)
	}
	return &junkSession{c: c, mailbox: mailbox, uidValidity: data.UIDValidity, numMessages: data.NumMessages, junked: junked}, nil
}

func (t *junkSession) close() {
	_ = t.c.Logout().Wait()
	_ = t.c.Close()
}

// siftMessages returns the messages in fetchSet that Sift moved to Junk, keyed by UID.
func (t *junkSession) siftMessages(fetchSet goimap.NumSet) (map[uint32]db.EmailEvent, error) {
	msgs, err := t.c.Fetch(fetchSet, &goimap.FetchOptions{UID: true, Envelope: true}).Collect()
	if err != nil {
		return nil, fmt.Errorf("fetch %s: %w", t.mailbox, err)
	}
	out := map[uint32]db.EmailEvent{}
	for _, m := range msgs {
		if m.Envelope == nil {
			continue
		}
		if ev, ok := t.junked[db.NormalizeMessageID(m.Envelope.MessageID)]; ok {
			out[uint32(m.UID)] = ev
		}
	}
	return out, nil
}

func ListJunk(store *db.Store) (JunkListing, error) {
	t, err := openJunk(store, true)
	if err != nil {
		return JunkListing{}, err
	}
	defer t.close()

	listing := JunkListing{Mailbox: t.mailbox, UIDValidity: t.uidValidity, Items: []JunkItem{}}
	if t.numMessages == 0 || len(t.junked) == 0 {
		return listing, nil
	}
	var all goimap.SeqSet
	all.AddRange(1, 0)
	found, err := t.siftMessages(all)
	if err != nil {
		return JunkListing{}, err
	}
	for uid, ev := range found {
		listing.Items = append(listing.Items, JunkItem{
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

// DeleteFromJunk permanently removes the given Junk UIDs that Sift put there and returns how many it removed.
func DeleteFromJunk(store *db.Store, uidValidity uint32, uids []uint32) (int, error) {
	if len(uids) == 0 {
		return 0, nil
	}
	t, err := openJunk(store, false)
	if err != nil {
		return 0, err
	}
	defer t.close()
	if t.uidValidity != uidValidity {
		return 0, errors.New("the Junk mailbox changed since it was listed, reload and try again")
	}

	var requested goimap.UIDSet
	for _, u := range uids {
		requested.AddNum(goimap.UID(u))
	}
	found, err := t.siftMessages(requested)
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
	if err := expungeUIDs(t.c, target); err != nil {
		return 0, err
	}
	if err := store.MarkJunkedEventsDeleted(messageIDs); err != nil {
		return 0, err
	}
	return len(found), nil
}
