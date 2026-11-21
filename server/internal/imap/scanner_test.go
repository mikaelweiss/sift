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
	"github.com/mikaelweiss/eclean/server/internal/classifier"
	"github.com/mikaelweiss/eclean/server/internal/db"
	"github.com/mikaelweiss/eclean/server/internal/jev"
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

func startIMAPServer(t *testing.T, inbox int) string {
	t.Helper()
	mem := imapmemserver.New()
	user := imapmemserver.NewUser("user", "pass")
	mem.AddUser(user)
	srv := imapserver.New(&imapserver.Options{
		NewSession: func(*imapserver.Conn) (imapserver.Session, *imapserver.GreetingData, error) {
			return mem.NewSession(), nil, nil
		},
		Caps:         goimap.CapSet{goimap.CapIMAP4rev1: {}, goimap.CapIMAP4rev2: {}},
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
	for _, name := range []string{"Archive", "Trash"} {
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
	return ln.Addr().String()
}

func runScan(t *testing.T, messages int, dryRun bool) (db.ScanJob, *slowEvaluator, string, time.Duration) {
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
	cfg.SpamAction = "trash"
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
			return *got, eval, addr, elapsed
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
	job, eval, addr, elapsed := runScan(t, messages, true)
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
}

func TestScanLiveMovesSpamToTrash(t *testing.T) {
	const messages = 400
	job, _, addr, _ := runScan(t, messages, false)
	if job.Status != "completed" {
		t.Fatalf("status %q: %s", job.Status, job.ErrorMsg)
	}
	if got := mailboxCount(t, addr, "Trash"); got != messages/4 {
		t.Fatalf("Trash has %d messages, want %d", got, messages/4)
	}
	if got := mailboxCount(t, addr, "INBOX") + mailboxCount(t, addr, "Archive"); got != messages-messages/4 {
		t.Fatalf("INBOX and Archive hold %d messages, want %d", got, messages-messages/4)
	}
}
