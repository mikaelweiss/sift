package imap

import (
	"errors"
	"fmt"
	"strings"

	goimap "github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"
)

// spamMailboxes names where spam goes and where the user's own deletions live.
type spamMailboxes struct {
	junk  string
	trash string
}

func discoverSpamMailboxes(c *imapclient.Client) spamMailboxes {
	boxes := spamMailboxes{junk: "Junk", trash: "Deleted Messages"}
	list, err := c.List("", "*", nil).Collect()
	if err != nil {
		return boxes
	}
	junkFound, trashFound := false, false
	for _, m := range list {
		if !junkFound && hasAttr(m.Attrs, goimap.MailboxAttrJunk) {
			boxes.junk, junkFound = m.Mailbox, true
		}
		if !trashFound && hasAttr(m.Attrs, goimap.MailboxAttrTrash) {
			boxes.trash, trashFound = m.Mailbox, true
		}
	}
	for _, m := range list {
		switch strings.ToLower(m.Mailbox) {
		case "junk", "spam", "bulk mail":
			if !junkFound {
				boxes.junk, junkFound = m.Mailbox, true
			}
		case "deleted messages", "trash":
			if !trashFound {
				boxes.trash, trashFound = m.Mailbox, true
			}
		}
	}
	return boxes
}

// applySpamAction moves spam into Junk, which trains iCloud's filter. A delete moves first and then expunges the
// moved copies from Junk. The client is left with source selected. Mail already in Junk or the user's Trash is not
// moved again.
func applySpamAction(c *imapclient.Client, uids []goimap.UID, action, source string, boxes spamMailboxes) error {
	if len(uids) == 0 {
		return nil
	}
	var uidSet goimap.UIDSet
	for _, u := range uids {
		uidSet.AddNum(u)
	}

	switch action {
	case "junk":
		if source == boxes.junk || source == boxes.trash {
			return nil
		}
		if _, err := c.Move(uidSet, boxes.junk).Wait(); err != nil {
			return fmt.Errorf("move to %s: %w", boxes.junk, err)
		}
		return nil
	case "delete":
		if source == boxes.junk {
			return expungeUIDs(c, uidSet)
		}
		moved, err := c.Move(uidSet, boxes.junk).Wait()
		if err != nil {
			return fmt.Errorf("move to %s: %w", boxes.junk, err)
		}
		var dest goimap.UIDSet
		if moved != nil {
			dest, _ = moved.DestUIDs.(goimap.UIDSet)
		}
		if len(dest) == 0 {
			return errors.New("server did not report the moved UIDs, so the copies in Junk were kept")
		}
		if _, err := c.Select(boxes.junk, nil).Wait(); err != nil {
			return fmt.Errorf("select %s: %w", boxes.junk, err)
		}
		expungeErr := expungeUIDs(c, dest)
		if _, err := c.Select(source, nil).Wait(); err != nil {
			return errors.Join(expungeErr, fmt.Errorf("reselect %s: %w", source, err))
		}
		return expungeErr
	default:
		return fmt.Errorf("unknown spam action %q", action)
	}
}

// expungeUIDs removes exactly these UIDs. A plain EXPUNGE would also remove anything else flagged \Deleted.
func expungeUIDs(c *imapclient.Client, uids goimap.UIDSet) error {
	if err := c.Store(uids, &goimap.StoreFlags{Op: goimap.StoreFlagsAdd, Silent: true, Flags: []goimap.Flag{goimap.FlagDeleted}}, nil).Close(); err != nil {
		return fmt.Errorf("mark deleted: %w", err)
	}
	if err := c.UIDExpunge(uids).Close(); err != nil {
		return fmt.Errorf("expunge: %w", err)
	}
	return nil
}
