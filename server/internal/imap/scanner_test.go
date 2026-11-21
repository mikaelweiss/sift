package imap

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	goimap "github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"
	"github.com/emersion/go-imap/v2/imapserver"
	"github.com/emersion/go-imap/v2/imapserver/imapmemserver"
	"github.com/mikaelweiss/sift/server/internal/classifier"
	"github.com/mikaelweiss/sift/server/internal/db"
	"github.com/mikaelweiss/sift/server/internal/jev"
)

const jevLatency = 50 * time.Millisecond

// slowEvaluator stands in for Jev: fixed latency, and every message whose subject starts with "SPAM" scores high.
type slowEvaluator struct {
	inFlight, peak atomic.Int32
}

func (e *slowEvaluator) EvaluateNoul(ctx context.Context, state any, questions map[string]jev.NoulQuestion) (map[string]float64, error) {
	n := e.inFlight.Add(1)
	defer e.inFlight.Add(-1)
	for {
		p := e.peak.Load()
		if n <= p || e.peak.CompareAndSwap(p, n) {
			break
		}
	}
	select {
	case <-time.After(jevLatency):
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	score := 0.1
	if strings.HasPrefix(state.(map[string]any)["subject"].(string), "SPAM") {
		score = 0.99
	}
	scores := map[string]float64{}
	for id := range questions {
		scores[id] = score
	}
	return scores, nil
}

func (e *slowEvaluator) VerifyKey(context.Context) error { return nil }

var testServerCaps = goimap.CapSet{goimap.CapIMAP4rev1: {}, goimap.CapIMAP4rev2: {}}

// trashSpam is how many extra spam messages startIMAPServer puts in Trash.
var trashSpam = 0

func startIMAPServer(t *testing.T, inbox int) string {
	t.Helper()
	mem := imapmemserver.New()
	user := imapmemserver.NewUser("user", "pass")
	mem.AddUser(user)
	srv := imapserver.New(&imapserver.Options{
		NewSession: func(*imapserver.Conn) (imapserver.Session, *imapserver.GreetingData, error) {
			return mem.NewSession(), nil, nil
		},
		Caps:         testServerCaps,
		InsecureAuth: true,
	})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })

	c, err := imapclient.DialInsecure(ln.Addr().String(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err := c.Login("user", "pass").Wait(); err != nil {
		t.Fatal(err)
	}
	if err := c.Create("INBOX", nil).Wait(); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"Archive", "Junk", "Trash"} {
		if err := c.Create(name, nil).Wait(); err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < inbox; i++ {
		subject := fmt.Sprintf("Hello %d", i)
		if i%4 == 0 {
			subject = fmt.Sprintf("SPAM %d", i)
		}
		raw := fmt.Sprintf("From: Sender <s%d@example.com>\r\nTo: user@example.com\r\nSubject: %s\r\nDate: %s\r\nMessage-ID: <%d@example.com>\r\nContent-Type: text/plain\r\n\r\nBody %d\r\n",
			i, subject, time.Now().Add(-48*time.Hour).Format(time.RFC1123Z), i, i)
		mailbox := "INBOX"
		if i%3 == 0 {
			mailbox = "Archive"
		}
		cmd := c.Append(mailbox, int64(len(raw)), nil)
		if _, err := cmd.Write([]byte(raw)); err != nil {
			t.Fatal(err)
		}
		if err := cmd.Close(); err != nil {
			t.Fatal(err)
		}
		if _, err := cmd.Wait(); err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < trashSpam; i++ {
		raw := fmt.Sprintf("From: Spammer <spam%d@example.com>\r\nSubject: SPAM in trash %d\r\nDate: %s\r\nMessage-ID: <trash-%d@example.com>\r\n\r\nBuy now\r\n",
			i, i, time.Now().Add(-24*time.Hour).Format(time.RFC1123Z), i)
		cmd := c.Append("Trash", int64(len(raw)), nil)
		if _, err := cmd.Write([]byte(raw)); err != nil {
			t.Fatal(err)
		}
		if err := cmd.Close(); err != nil {
			t.Fatal(err)
		}
		if _, err := cmd.Wait(); err != nil {
			t.Fatal(err)
		}
	}
	return ln.Addr().String()
}

type scanRun struct {
	job     db.ScanJob
	eval    *slowEvaluator
	addr    string
	store   *db.Store
	scanner *Scanner
	elapsed time.Duration
}

func runScan(t *testing.T, messages int, dryRun bool, configure ...func(*db.AppSettings)) scanRun {
	t.Helper()
	addr := startIMAPServer(t, messages)
	dialScanClient = func(host string, port int, username, password string, _ *imapclient.Options) (*imapclient.Client, error) {
		c, err := imapclient.DialInsecure(addr, nil)
		if err != nil {
			return nil, err
		}
		return c, c.Login(username, password).Wait()
	}
	t.Cleanup(func() { dialScanClient = dialAndLogin })

	store, err := db.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := store.GetSettings()
	if err != nil {
		t.Fatal(err)
	}
	cfg.IMAPUsername, cfg.IMAPPassword = "user", "pass"
	for _, fn := range configure {
		fn(&cfg)
	}
	if err := store.SaveSettings(cfg); err != nil {
		t.Fatal(err)
	}

	eval := &slowEvaluator{}
	scanner := NewScanner(store, classifier.NewEngine(store, eval), nil)
	started := time.Now()
	job, err := scanner.Start("all", dryRun, 0)
	if err != nil {
		t.Fatal(err)
	}
	for {
		got, err := store.GetScanJob(job.ID)
		if err != nil {
			t.Fatal(err)
		}
		if got.Status != "running" {
			elapsed := time.Since(started)
			t.Logf("%d messages in %v, peak Jev concurrency %d", messages, elapsed.Round(time.Millisecond), eval.peak.Load())
			return scanRun{job: *got, eval: eval, addr: addr, store: store, scanner: scanner, elapsed: elapsed}
		}
		if time.Since(started) > time.Minute {
			t.Fatal("scan did not finish")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func mailboxCount(t *testing.T, addr, mailbox string) uint32 {
	t.Helper()
	c, err := imapclient.DialInsecure(addr, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err := c.Login("user", "pass").Wait(); err != nil {
		t.Fatal(err)
	}
	data, err := c.Select(mailbox, &goimap.SelectOptions{ReadOnly: true}).Wait()
	if err != nil {
		t.Fatal(err)
	}
	return data.NumMessages
}

func TestScanDryRunClassifiesEveryMessageConcurrently(t *testing.T) {
	const messages = 1000
	run := runScan(t, messages, true)
	job, eval, addr, elapsed := run.job, run.eval, run.addr, run.elapsed
	if job.Status != "completed" {
		t.Fatalf("status %q: %s", job.Status, job.ErrorMsg)
	}
	if job.ScannedMessages != messages || job.SpamFound != messages/4 {
		t.Fatalf("scanned %d spam %d, want %d and %d", job.ScannedMessages, job.SpamFound, messages, messages/4)
	}
	archived := uint32((messages + 2) / 3)
	if job.Checkpoints["Archive"] != archived || job.Checkpoints["INBOX"] != messages-archived {
		t.Fatalf("checkpoints %v, want Archive %d and INBOX %d", job.Checkpoints, archived, messages-archived)
	}
	if got := mailboxCount(t, addr, "INBOX") + mailboxCount(t, addr, "Archive"); got != messages {
		t.Fatalf("dry run left %d messages, want %d", got, messages)
	}
	if eval.peak.Load() < scanConcurrency/2 {
		t.Fatalf("peak Jev concurrency %d, want close to %d", eval.peak.Load(), scanConcurrency)
	}
	serial := time.Duration(messages/scanConcurrency) * jevLatency
	if elapsed > 3*serial {
		t.Fatalf("scan took %v, want near %v", elapsed, serial)
	}
	if matches, err := run.store.ListScanMatches(job.ID); err != nil || len(matches) != messages/4 {
		t.Fatalf("listed %d matches (err %v), want all %d", len(matches), err, messages/4)
	}
}

func TestScanLiveMovesSpamToJunk(t *testing.T) {
	const messages = 400
	run := runScan(t, messages, false)
	job, addr := run.job, run.addr
	if job.Status != "completed" {
		t.Fatalf("status %q: %s", job.Status, job.ErrorMsg)
	}
	if got := mailboxCount(t, addr, "Junk"); got != messages/4 {
		t.Fatalf("Junk has %d messages, want %d", got, messages/4)
	}
	if got := mailboxCount(t, addr, "INBOX") + mailboxCount(t, addr, "Archive"); got != messages-messages/4 {
		t.Fatalf("INBOX and Archive hold %d messages, want %d", got, messages-messages/4)
	}
	if matches, err := run.store.ListScanMatches(job.ID); err != nil || len(matches) != messages/4 {
		t.Fatalf("listed %d matches (err %v), want all %d", len(matches), err, messages/4)
	}
}

func TestJunkListsAndDeletesOnlySiftMail(t *testing.T) {
	const messages = 400
	run := runScan(t, messages, false)
	spam := messages / 4

	c, err := imapclient.DialInsecure(run.addr, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err := c.Login("user", "pass").Wait(); err != nil {
		t.Fatal(err)
	}
	own := "From: Friend <friend@example.com>\r\nSubject: Filed as junk elsewhere\r\nMessage-ID: <own@example.com>\r\n\r\nHi\r\n"
	appendCmd := c.Append("Junk", int64(len(own)), nil)
	_, _ = appendCmd.Write([]byte(own))
	_ = appendCmd.Close()
	appended, err := appendCmd.Wait()
	if err != nil {
		t.Fatal(err)
	}

	listing, err := ListJunk(run.store)
	if err != nil {
		t.Fatal(err)
	}
	if len(listing.Items) != spam {
		t.Fatalf("listed %d junk items, want the %d Sift moved", len(listing.Items), spam)
	}

	var uids []uint32
	for _, item := range listing.Items[:40] {
		uids = append(uids, item.UID)
	}
	uids = append(uids, uint32(appended.UID))
	deleted, err := DeleteFromJunk(run.store, listing.UIDValidity, uids)
	if err != nil {
		t.Fatal(err)
	}
	if deleted != 40 {
		t.Fatalf("deleted %d, want 40", deleted)
	}
	if got := mailboxCount(t, run.addr, "Junk"); got != uint32(spam-40+1) {
		t.Fatalf("Junk holds %d, want %d with the other message kept", got, spam-40+1)
	}
	if listing, err = ListJunk(run.store); err != nil || len(listing.Items) != spam-40 {
		t.Fatalf("relisted %d items (err %v), want %d", len(listing.Items), err, spam-40)
	}

	if _, err := DeleteFromJunk(run.store, listing.UIDValidity+1, uids); err == nil {
		t.Fatal("delete with a stale UIDVALIDITY succeeded")
	}
}

func TestApplyDryRunMovesSpamAndRecordsEveryVerdict(t *testing.T) {
	const messages = 400
	run := runScan(t, messages, true)
	if _, err := run.scanner.Apply(run.job.ID); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(30 * time.Second)
	for {
		job, err := run.store.GetScanJob(run.job.ID)
		if err != nil {
			t.Fatal(err)
		}
		if job.Status == "applied" {
			break
		}
		if job.Status != "applying" || time.Now().After(deadline) {
			t.Fatalf("apply ended in %q: %s", job.Status, job.ErrorMsg)
		}
		time.Sleep(10 * time.Millisecond)
	}
	if got := mailboxCount(t, run.addr, "Junk"); got != messages/4 {
		t.Fatalf("Junk holds %d, want %d", got, messages/4)
	}
	pending, err := run.store.ListPendingScanResults(run.job.ID)
	if err != nil || len(pending) != 0 {
		t.Fatalf("%d results still pending (err %v)", len(pending), err)
	}
	junked, err := run.store.ListJunkedEvents()
	if err != nil || len(junked) != messages/4 {
		t.Fatalf("recorded %d junk events (err %v), want %d", len(junked), err, messages/4)
	}
}

func TestPermanentDeleteGoesThroughJunkAndLeavesNoCopy(t *testing.T) {
	const messages = 200
	run := runScan(t, messages, false, func(cfg *db.AppSettings) { cfg.DeleteEnabled = true })
	if run.job.Status != "completed" {
		t.Fatalf("status %q: %s", run.job.Status, run.job.ErrorMsg)
	}
	if got := mailboxCount(t, run.addr, "Junk"); got != 0 {
		t.Fatalf("Junk still holds %d deleted messages", got)
	}
	if got := mailboxCount(t, run.addr, "INBOX") + mailboxCount(t, run.addr, "Archive"); got != messages-messages/4 {
		t.Fatalf("INBOX and Archive hold %d, want %d", got, messages-messages/4)
	}
}

// iCloud advertises UIDPLUS but not MOVE, so moves fall back to COPY + STORE + UID EXPUNGE.
func TestPermanentDeleteWorksWithoutMoveSupport(t *testing.T) {
	testServerCaps = goimap.CapSet{goimap.CapIMAP4rev1: {}, goimap.CapUIDPlus: {}}
	t.Cleanup(func() { testServerCaps = goimap.CapSet{goimap.CapIMAP4rev1: {}, goimap.CapIMAP4rev2: {}} })

	const messages = 120
	run := runScan(t, messages, false, func(cfg *db.AppSettings) { cfg.DeleteEnabled = true })
	if run.job.Status != "completed" {
		t.Fatalf("status %q: %s", run.job.Status, run.job.ErrorMsg)
	}
	if got := mailboxCount(t, run.addr, "Junk"); got != 0 {
		t.Fatalf("Junk still holds %d deleted messages", got)
	}
	if got := mailboxCount(t, run.addr, "INBOX") + mailboxCount(t, run.addr, "Archive"); got != messages-messages/4 {
		t.Fatalf("INBOX and Archive hold %d, want %d", got, messages-messages/4)
	}
}

func TestSpamInTrashMovesToJunk(t *testing.T) {
	trashSpam = 3
	t.Cleanup(func() { trashSpam = 0 })

	run := runScan(t, 40, false)
	if run.job.Status != "completed" {
		t.Fatalf("status %q: %s", run.job.Status, run.job.ErrorMsg)
	}
	if got := mailboxCount(t, run.addr, "Trash"); got != 0 {
		t.Fatalf("Trash still holds %d spam", got)
	}
	if got := mailboxCount(t, run.addr, "Junk"); got != 40/4+3 {
		t.Fatalf("Junk holds %d, want %d", got, 40/4+3)
	}
}
