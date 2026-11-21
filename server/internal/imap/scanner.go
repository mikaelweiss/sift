package imap

import (
	"context"
	"errors"
	"fmt"
	"log"
	"sort"
	"sync"
	"time"

	goimap "github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"
	"github.com/google/uuid"
	"github.com/mikaelweiss/sift/server/internal/abuse"
	"github.com/mikaelweiss/sift/server/internal/classifier"
	"github.com/mikaelweiss/sift/server/internal/db"
	"github.com/mikaelweiss/sift/server/internal/jev"
)

const (
	scanBatchSize   = 50
	scanConcurrency = jev.MaxConcurrentRequests
	scanFetchConns  = 8
	scanWindow      = 2 * scanFetchConns
	maxFetchBytes   = 65536
)

var dialScanClient = dialAndLogin

type Scanner struct {
	store      *db.Store
	classifier *classifier.Engine
	abuseSvc   *abuse.Service

	mu           sync.Mutex
	activeJobID  string
	cancelActive context.CancelFunc
	paused       bool

	OnProgress func(job db.ScanJob)
}

func NewScanner(store *db.Store, engine *classifier.Engine, abuseSvc *abuse.Service) *Scanner {
	return &Scanner{
		store:      store,
		classifier: engine,
		abuseSvc:   abuseSvc,
	}
}

func (s *Scanner) Start(dateRange string, dryRun bool, ratePerSec float64) (db.ScanJob, error) {
	s.mu.Lock()
	if s.activeJobID != "" {
		s.mu.Unlock()
		return db.ScanJob{}, errors.New("a scan job is already running")
	}
	if dateRange != "30d" && dateRange != "1y" && dateRange != "all" {
		dateRange = "30d"
	}
	if ratePerSec <= 0 {
		ratePerSec = 10
	}
	job := db.ScanJob{
		ID:          uuid.NewString(),
		DateRange:   dateRange,
		DryRun:      dryRun,
		RatePerSec:  ratePerSec,
		Status:      "running",
		Checkpoints: map[string]uint32{},
		Summary:     map[string]int{},
	}
	if err := s.store.SaveScanJob(job); err != nil {
		s.mu.Unlock()
		return db.ScanJob{}, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	s.activeJobID = job.ID
	s.cancelActive = cancel
	s.paused = false
	s.mu.Unlock()

	s.emit(job)
	go s.runJob(ctx, job)
	return job, nil
}

func (s *Scanner) Pause(id string) (db.ScanJob, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.activeJobID != id {
		return db.ScanJob{}, errors.New("scan job is not active")
	}
	s.paused = true
	job, err := s.store.GetScanJob(id)
	if err != nil || job == nil {
		return db.ScanJob{}, errors.New("scan job not found")
	}
	job.Status = "paused"
	_ = s.store.SaveScanJob(*job)
	s.emit(*job)
	return *job, nil
}

func (s *Scanner) Resume(id string) (db.ScanJob, error) {
	s.mu.Lock()
	if s.activeJobID == id && s.paused {
		s.paused = false
		job, err := s.store.GetScanJob(id)
		s.mu.Unlock()
		if err != nil || job == nil {
			return db.ScanJob{}, errors.New("scan job not found")
		}
		job.Status = "running"
		_ = s.store.SaveScanJob(*job)
		s.emit(*job)
		return *job, nil
	}
	if s.activeJobID != "" {
		s.mu.Unlock()
		return db.ScanJob{}, errors.New("another scan job is already running")
	}
	job, err := s.store.GetScanJob(id)
	if err != nil || job == nil {
		s.mu.Unlock()
		return db.ScanJob{}, errors.New("scan job not found")
	}
	if job.Status != "paused" && job.Status != "failed" {
		s.mu.Unlock()
		return *job, nil
	}
	job.Status = "running"
	job.ErrorMsg = ""
	_ = s.store.SaveScanJob(*job)
	ctx, cancel := context.WithCancel(context.Background())
	s.activeJobID = job.ID
	s.cancelActive = cancel
	s.paused = false
	s.mu.Unlock()

	s.emit(*job)
	go s.runJob(ctx, *job)
	return *job, nil
}

func (s *Scanner) Cancel(id string) (db.ScanJob, error) {
	s.mu.Lock()
	if s.activeJobID == id && s.cancelActive != nil {
		s.cancelActive()
		s.paused = false
	}
	s.mu.Unlock()

	job, err := s.store.GetScanJob(id)
	if err != nil || job == nil {
		return db.ScanJob{}, errors.New("scan job not found")
	}
	job.Status = "cancelled"
	_ = s.store.SaveScanJob(*job)
	s.emit(*job)
	return *job, nil
}

func (s *Scanner) Apply(id string) (db.ScanJob, error) {
	s.mu.Lock()
	if s.activeJobID != "" {
		s.mu.Unlock()
		return db.ScanJob{}, errors.New("a scan job is already active")
	}
	job, err := s.store.GetScanJob(id)
	if err != nil || job == nil {
		s.mu.Unlock()
		return db.ScanJob{}, errors.New("scan job not found")
	}
	if !job.DryRun {
		s.mu.Unlock()
		return db.ScanJob{}, errors.New("only dry run jobs can be applied")
	}
	if job.Status != "completed" && job.Status != "failed" {
		s.mu.Unlock()
		return db.ScanJob{}, fmt.Errorf("cannot apply scan in status %q", job.Status)
	}
	job.Status = "applying"
	job.ErrorMsg = ""
	if err := s.store.SaveScanJob(*job); err != nil {
		s.mu.Unlock()
		return db.ScanJob{}, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	s.activeJobID = job.ID
	s.cancelActive = cancel
	s.paused = false
	s.mu.Unlock()

	s.emit(*job)
	go s.runApply(ctx, *job)
	return *job, nil
}

func (s *Scanner) isPaused() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.paused
}

func (s *Scanner) clearActive(id string) {
	s.mu.Lock()
	if s.activeJobID == id {
		s.activeJobID = ""
		s.cancelActive = nil
		s.paused = false
	}
	s.mu.Unlock()
}

type folderPlan struct {
	mailbox string
	uids    []goimap.UID
}

type classifiedMsg struct {
	uid      goimap.UID
	input    classifier.EmailInput
	decision classifier.Decision
	err      error
}

type scanBatch struct {
	mailbox     string
	uids        []goimap.UID
	uidValidity uint32
	maxUID      uint32
	snap        *classifier.Snapshot
	msgs        []classifiedMsg
	err         error
	fetched     chan struct{}
	done        sync.WaitGroup
}

type classifyTask struct {
	batch *scanBatch
	idx   int
}

// scanProgress guards the job shared by the IMAP loop, the fetchers, and the classify workers.
type scanProgress struct {
	mu       sync.Mutex
	job      db.ScanJob
	lastEmit time.Time
}

func (p *scanProgress) update(fn func(*db.ScanJob)) db.ScanJob {
	p.mu.Lock()
	defer p.mu.Unlock()
	fn(&p.job)
	return cloneScanJob(p.job)
}

// Only the first 64 KB of each message (headers + text body) is fetched to skip multi-MB attachments.
var scanBodySection = &goimap.FetchItemBodySection{
	Peek:    true,
	Partial: &goimap.SectionPartial{Offset: 0, Size: maxFetchBytes},
}

// fetchConn is a read-only IMAP session. iCloud serves message bodies slowly per session
// but scales almost linearly with parallel sessions.
type fetchConn struct {
	c           *imapclient.Client
	selected    string
	uidValidity uint32
}

func (f *fetchConn) selectMailbox(mailbox string) error {
	if f.selected == mailbox {
		return nil
	}
	data, err := f.c.Select(mailbox, &goimap.SelectOptions{ReadOnly: true}).Wait()
	if err != nil {
		f.selected = ""
		return err
	}
	f.selected, f.uidValidity = mailbox, data.UIDValidity
	return nil
}

func dialFetchConns(cfg db.AppSettings, n int) ([]*fetchConn, error) {
	conns := make([]*fetchConn, n)
	errs := make([]error, n)
	var wg sync.WaitGroup
	for i := range conns {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c, err := dialScanClient(cfg.IMAPHost, cfg.IMAPPort, cfg.IMAPUsername, cfg.IMAPPassword, nil)
			if err != nil {
				errs[i] = err
				return
			}
			conns[i] = &fetchConn{c: c}
		}()
	}
	wg.Wait()

	var ok []*fetchConn
	for i, f := range conns {
		if f != nil {
			ok = append(ok, f)
		} else {
			log.Printf("scan fetch connection %d failed: %v", i, errs[i])
		}
	}
	if len(ok) == 0 {
		return nil, errs[0]
	}
	return ok, nil
}

// runJob pulls message bodies over a pool of read-only sessions and classifies them as they arrive.
// The primary session alone moves and deletes, in batch order, so checkpoints stay monotonic.
func (s *Scanner) runJob(ctx context.Context, job db.ScanJob) {
	defer s.clearActive(job.ID)

	if job.Checkpoints == nil {
		job.Checkpoints = map[string]uint32{}
	}
	progress := &scanProgress{job: job, lastEmit: time.Now()}
	fail := func(err error) {
		s.persist(progress.update(func(j *db.ScanJob) {
			j.Status = "failed"
			j.ErrorMsg = err.Error()
		}))
	}
	markCancelled := func() {
		s.persist(progress.update(func(j *db.ScanJob) { j.Status = "cancelled" }))
	}

	cfg, err := s.store.GetSettings()
	if err != nil {
		fail(err)
		return
	}

	type dialResult struct {
		conns []*fetchConn
		err   error
	}
	poolReady := make(chan dialResult, 1)
	go func() {
		conns, err := dialFetchConns(cfg, scanFetchConns)
		poolReady <- dialResult{conns, err}
	}()

	c, err := dialScanClient(cfg.IMAPHost, cfg.IMAPPort, cfg.IMAPUsername, cfg.IMAPPassword, nil)
	if err != nil {
		if pool := <-poolReady; pool.err == nil {
			closeFetchConns(pool.conns)
		}
		fail(err)
		return
	}
	defer c.Close()

	trashMailbox := discoverTrashMailbox(c)
	mailboxes := DiscoverMailboxes(c, true)

	pool := <-poolReady
	if pool.err != nil {
		fail(pool.err)
		return
	}
	fetchers := pool.conns
	defer closeFetchConns(fetchers)

	if ctx.Err() != nil {
		markCancelled()
		return
	}
	plans, totalAcrossFolders := planFolders(fetchers, mailboxes, buildSearchCriteria(job.DateRange, time.Now().UTC()), job.Checkpoints)
	if job.TotalMessages == 0 || totalAcrossFolders > job.TotalMessages {
		s.persist(progress.update(func(j *db.ScanJob) { j.TotalMessages = totalAcrossFolders }))
	}

	tasks := make(chan classifyTask, scanConcurrency)
	var workers sync.WaitGroup
	for i := 0; i < scanConcurrency; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for t := range tasks {
				s.classify(ctx, t, progress)
				t.batch.done.Done()
			}
		}()
	}
	defer func() {
		close(tasks)
		workers.Wait()
	}()

	requests := make(chan *scanBatch, scanWindow)
	var fetching sync.WaitGroup
	for _, f := range fetchers {
		fetching.Add(1)
		go func() {
			defer fetching.Done()
			for b := range requests {
				s.fetchBatch(ctx, f, b, job.DryRun, tasks, progress)
			}
		}()
	}
	stopFetching := func() {
		close(requests)
		fetching.Wait()
	}

	err = s.dispatchAndFinish(ctx, c, plans, job, trashMailbox, requests, progress)
	stopFetching()
	if err != nil {
		if ctx.Err() != nil {
			markCancelled()
		} else {
			fail(err)
		}
		return
	}

	s.persist(progress.update(func(j *db.ScanJob) {
		j.CurrentMailbox = ""
		j.Status = "completed"
	}))
	_ = c.Logout().Wait()
}

func closeFetchConns(conns []*fetchConn) {
	for _, f := range conns {
		_ = f.c.Logout().Wait()
		_ = f.c.Close()
	}
}

// planFolders searches every mailbox in parallel across the fetch sessions.
func planFolders(fetchers []*fetchConn, mailboxes []string, criteria *goimap.SearchCriteria, checkpoints map[string]uint32) ([]folderPlan, int) {
	found := make([][]goimap.UID, len(mailboxes))
	next := make(chan int, len(mailboxes))
	for i := range mailboxes {
		next <- i
	}
	close(next)
	var wg sync.WaitGroup
	for _, f := range fetchers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range next {
				if err := f.selectMailbox(mailboxes[i]); err != nil {
					log.Printf("scan skip folder %q: %v", mailboxes[i], err)
					continue
				}
				data, err := f.c.UIDSearch(criteria, nil).Wait()
				if err != nil {
					log.Printf("scan search folder %q failed: %v", mailboxes[i], err)
					continue
				}
				found[i] = data.AllUIDs()
			}
		}()
	}
	wg.Wait()

	var plans []folderPlan
	total := 0
	for i, uids := range found {
		sort.Slice(uids, func(a, b int) bool { return uids[a] < uids[b] })
		total += len(uids)
		var pending []goimap.UID
		for _, u := range uids {
			if uint32(u) > checkpoints[mailboxes[i]] {
				pending = append(pending, u)
			}
		}
		if len(pending) > 0 {
			plans = append(plans, folderPlan{mailbox: mailboxes[i], uids: pending})
		}
	}
	return plans, total
}

func (s *Scanner) dispatchAndFinish(ctx context.Context, c *imapclient.Client, plans []folderPlan, job db.ScanJob, trashMailbox string, requests chan<- *scanBatch, progress *scanProgress) error {
	actions := &actionConn{c: c}
	var inFlight []*scanBatch
	for _, plan := range plans {
		for start := 0; start < len(plan.uids); start += scanBatchSize {
			if len(inFlight) >= scanWindow {
				if err := s.finishBatch(ctx, actions, inFlight[0], job, trashMailbox, progress); err != nil {
					return err
				}
				inFlight = inFlight[1:]
			}
			end := min(start+scanBatchSize, len(plan.uids))
			b := &scanBatch{mailbox: plan.mailbox, uids: plan.uids[start:end], fetched: make(chan struct{})}
			select {
			case requests <- b:
			case <-ctx.Done():
				return ctx.Err()
			}
			inFlight = append(inFlight, b)
		}
	}
	for _, b := range inFlight {
		if err := s.finishBatch(ctx, actions, b, job, trashMailbox, progress); err != nil {
			return err
		}
	}
	return nil
}

func (s *Scanner) fetchBatch(ctx context.Context, f *fetchConn, b *scanBatch, dryRun bool, tasks chan<- classifyTask, progress *scanProgress) {
	defer close(b.fetched)
	if err := s.waitIfPaused(ctx); err != nil {
		b.err = err
		return
	}
	snap, err := s.classifier.Snapshot()
	if err != nil {
		b.err = err
		return
	}
	b.snap = snap
	if err := f.selectMailbox(b.mailbox); err != nil {
		b.err = fmt.Errorf("select %s: %w", b.mailbox, err)
		return
	}
	b.uidValidity = f.uidValidity

	var fetchSet goimap.UIDSet
	for _, u := range b.uids {
		fetchSet.AddNum(u)
	}
	msgs, err := f.c.Fetch(fetchSet, &goimap.FetchOptions{
		UID:          true,
		InternalDate: true,
		BodySection:  []*goimap.FetchItemBodySection{scanBodySection},
	}).Collect()
	if err != nil {
		b.err = fmt.Errorf("fetch batch in %s: %w", b.mailbox, err)
		return
	}

	alreadyProcessed := 0
	for _, msg := range msgs {
		uid := uint32(msg.UID)
		b.maxUID = max(b.maxUID, uid)
		if !dryRun {
			if exists, _ := s.store.HasEmailEvent(b.mailbox, b.uidValidity, uid); exists {
				alreadyProcessed++
				continue
			}
		}
		raw := extractBodyBytes(msg, scanBodySection)
		b.msgs = append(b.msgs, classifiedMsg{
			uid:   msg.UID,
			input: ParseRawMessage(b.uidValidity, uid, msg.InternalDate, raw),
		})
	}
	if alreadyProcessed > 0 {
		progress.update(func(j *db.ScanJob) { j.ScannedMessages += alreadyProcessed })
	}

	b.done.Add(len(b.msgs))
	for idx := range b.msgs {
		select {
		case tasks <- classifyTask{batch: b, idx: idx}:
		case <-ctx.Done():
			b.err = ctx.Err()
			b.done.Add(idx - len(b.msgs))
			return
		}
	}
}

func (s *Scanner) classify(ctx context.Context, t classifyTask, progress *scanProgress) {
	msg := &t.batch.msgs[t.idx]
	if err := s.waitIfPaused(ctx); err != nil {
		msg.err = err
		return
	}
	msg.decision, msg.err = t.batch.snap.Evaluate(ctx, msg.input)

	progress.mu.Lock()
	job := &progress.job
	job.ScannedMessages++
	dec := msg.decision
	if msg.err == nil && (dec.Action == "trash" || dec.Action == "delete") {
		job.SpamFound++
		if job.Summary == nil {
			job.Summary = map[string]int{}
		}
		job.Summary[dec.CategoryID]++
	}
	if time.Since(progress.lastEmit) < 300*time.Millisecond {
		progress.mu.Unlock()
		return
	}
	progress.lastEmit = time.Now()
	snapshot := cloneScanJob(*job)
	progress.mu.Unlock()
	s.emit(snapshot)
}

// actionConn is the primary session, selected read-write on whichever mailbox the next batch came from.
type actionConn struct {
	c           *imapclient.Client
	selected    string
	uidValidity uint32
}

func (a *actionConn) selectMailbox(mailbox string) error {
	if a.selected == mailbox {
		return nil
	}
	data, err := a.c.Select(mailbox, &goimap.SelectOptions{ReadOnly: false}).Wait()
	if err != nil {
		a.selected = ""
		return err
	}
	a.selected, a.uidValidity = mailbox, data.UIDValidity
	return nil
}

func (s *Scanner) finishBatch(ctx context.Context, actions *actionConn, b *scanBatch, job db.ScanJob, trashMailbox string, progress *scanProgress) error {
	<-b.fetched
	if b.err != nil {
		return b.err
	}
	b.done.Wait()
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if job.DryRun {
		s.recordDryRunBatch(job.ID, b)
	} else {
		if err := actions.selectMailbox(b.mailbox); err != nil {
			return fmt.Errorf("select %s for changes: %w", b.mailbox, err)
		}
		if actions.uidValidity != b.uidValidity {
			return fmt.Errorf("%s changed during the scan (UIDVALIDITY %d, was %d)", b.mailbox, actions.uidValidity, b.uidValidity)
		}
		s.applyBatch(ctx, actions.c, job.ID, b, trashMailbox)
	}
	s.persist(progress.update(func(j *db.ScanJob) {
		j.CurrentMailbox = b.mailbox
		if b.maxUID > 0 {
			j.LastUID = b.maxUID
			j.Checkpoints[b.mailbox] = b.maxUID
		}
	}))
	return nil
}

func (s *Scanner) recordDryRunBatch(jobID string, b *scanBatch) {
	var rows []db.ScanResult
	for _, r := range b.msgs {
		if r.err != nil {
			log.Printf("scan %s UID %d classify failed: %v", b.mailbox, r.uid, r.err)
			continue
		}
		rows = append(rows, scanResultRow(jobID, b, r, r.decision.Action, false))
	}
	if err := s.store.RecordScanResults(rows); err != nil {
		log.Printf("scan %s record dry run results failed: %v", b.mailbox, err)
	}
}

func scanResultRow(jobID string, b *scanBatch, r classifiedMsg, action string, applied bool) db.ScanResult {
	rawHdr := ""
	if (action == "trash" || action == "delete") && wAgeWithin7Days(r.input.EmailDate) {
		rawHdr = r.input.RawHeaders
	}
	return db.ScanResult{
		JobID:        jobID,
		Mailbox:      b.mailbox,
		UIDValidity:  b.uidValidity,
		UID:          uint32(r.uid),
		MessageID:    r.input.MessageID,
		Sender:       r.input.SenderEmail,
		SenderDomain: r.input.SenderDomain,
		Subject:      r.input.Subject,
		EmailDate:    r.input.EmailDate.UTC().Format(time.RFC3339),
		CategoryID:   r.decision.CategoryID,
		Confidence:   r.decision.Confidence,
		Action:       action,
		RawHeaders:   rawHdr,
		Applied:      applied,
	}
}

func (s *Scanner) applyBatch(ctx context.Context, c *imapclient.Client, jobID string, b *scanBatch, trashMailbox string) {
	var trashUIDs, deleteUIDs []goimap.UID
	for _, r := range b.msgs {
		if r.err != nil {
			log.Printf("scan %s UID %d classify failed: %v", b.mailbox, r.uid, r.err)
			continue
		}
		if r.decision.Action == "trash" && b.mailbox != trashMailbox {
			trashUIDs = append(trashUIDs, r.uid)
		} else if r.decision.Action == "delete" {
			deleteUIDs = append(deleteUIDs, r.uid)
		}
	}

	trashFailed := false
	if len(trashUIDs) > 0 {
		if actErr := applySpamActionBatch(c, trashUIDs, "trash", trashMailbox); actErr != nil {
			log.Printf("scan batch trash in %s failed: %v", b.mailbox, actErr)
			trashFailed = true
		}
	}
	deleteFailed := false
	if len(deleteUIDs) > 0 {
		if actErr := applySpamActionBatch(c, deleteUIDs, "delete", trashMailbox); actErr != nil {
			log.Printf("scan batch delete in %s failed: %v", b.mailbox, actErr)
			deleteFailed = true
		}
	}

	var events []db.EmailEvent
	var results []db.ScanResult
	var abuseCandidates []abuse.Candidate
	for _, r := range b.msgs {
		if r.err != nil {
			continue
		}
		actionTaken := r.decision.Action
		if actionTaken == "trash" && trashFailed && b.mailbox != trashMailbox {
			actionTaken = "error"
		} else if actionTaken == "delete" && deleteFailed {
			actionTaken = "error"
		}
		events = append(events, db.EmailEvent{
			Mailbox:      b.mailbox,
			UIDValidity:  b.uidValidity,
			UID:          uint32(r.uid),
			MessageID:    r.input.MessageID,
			Sender:       r.input.SenderEmail,
			SenderDomain: r.input.SenderDomain,
			Subject:      r.input.Subject,
			EmailDate:    r.input.EmailDate.UTC().Format(time.RFC3339),
			CategoryID:   r.decision.CategoryID,
			Confidence:   r.decision.Confidence,
			Action:       actionTaken,
			Source:       "backfill",
		})
		results = append(results, scanResultRow(jobID, b, r, actionTaken, true))
		if (actionTaken == "trash" || actionTaken == "delete") && wAgeWithin7Days(r.input.EmailDate) {
			abuseCandidates = append(abuseCandidates, abuse.Candidate{
				SenderEmail:  r.input.SenderEmail,
				SenderDomain: r.input.SenderDomain,
				Subject:      r.input.Subject,
				RawHeaders:   r.input.RawHeaders,
				CategoryID:   r.decision.CategoryID,
				Confidence:   r.decision.Confidence,
				EmailDate:    r.input.EmailDate,
			})
		}
	}
	if err := s.store.RecordEmailEvents(events); err != nil {
		log.Printf("scan %s record events failed: %v", b.mailbox, err)
	}
	if err := s.store.RecordScanResults(results); err != nil {
		log.Printf("scan %s record results failed: %v", b.mailbox, err)
	}
	if s.abuseSvc != nil {
		for _, cand := range abuseCandidates {
			_ = s.abuseSvc.Consider(ctx, cand)
		}
	}
}

func (s *Scanner) runApply(ctx context.Context, job db.ScanJob) {
	defer s.clearActive(job.ID)

	pending, err := s.store.ListPendingScanResults(job.ID)
	if err != nil {
		s.failJob(&job, err)
		return
	}
	if len(pending) == 0 {
		job.CurrentMailbox = ""
		job.Status = "applied"
		_ = s.store.SaveScanJob(job)
		s.emit(job)
		return
	}

	cfg, err := s.store.GetSettings()
	if err != nil {
		s.failJob(&job, err)
		return
	}
	c, err := dialScanClient(cfg.IMAPHost, cfg.IMAPPort, cfg.IMAPUsername, cfg.IMAPPassword, nil)
	if err != nil {
		s.failJob(&job, err)
		return
	}
	defer c.Close()

	trashMailbox := discoverTrashMailbox(c)

	// Group pending results by mailbox while preserving order.
	var mailboxOrder []string
	byMailbox := make(map[string][]db.ScanResult)
	for _, r := range pending {
		if _, exists := byMailbox[r.Mailbox]; !exists {
			mailboxOrder = append(mailboxOrder, r.Mailbox)
		}
		byMailbox[r.Mailbox] = append(byMailbox[r.Mailbox], r)
	}

	const applyChunkSize = 500
	for _, mailbox := range mailboxOrder {
		if ctx.Err() != nil {
			job.Status = "cancelled"
			_ = s.store.SaveScanJob(job)
			s.emit(job)
			return
		}

		job.CurrentMailbox = mailbox
		_ = s.store.SaveScanJob(job)
		s.emit(job)

		mbox, selErr := c.Select(mailbox, &goimap.SelectOptions{ReadOnly: false}).Wait()
		if selErr != nil {
			log.Printf("apply skip folder %q: %v", mailbox, selErr)
			continue
		}

		items := byMailbox[mailbox]
		for start := 0; start < len(items); start += applyChunkSize {
			if ctx.Err() != nil {
				job.Status = "cancelled"
				_ = s.store.SaveScanJob(job)
				s.emit(job)
				return
			}
			end := start + applyChunkSize
			if end > len(items) {
				end = len(items)
			}
			chunk := items[start:end]

			var trashUIDs []goimap.UID
			var deleteUIDs []goimap.UID
			for _, r := range chunk {
				if r.UIDValidity != mbox.UIDValidity {
					continue
				}
				if r.Action == "trash" && mailbox != trashMailbox {
					trashUIDs = append(trashUIDs, goimap.UID(r.UID))
				} else if r.Action == "delete" {
					deleteUIDs = append(deleteUIDs, goimap.UID(r.UID))
				}
			}

			trashFailed := false
			if len(trashUIDs) > 0 {
				if actErr := applySpamActionBatch(c, trashUIDs, "trash", trashMailbox); actErr != nil {
					log.Printf("apply batch trash in %s failed: %v", mailbox, actErr)
					trashFailed = true
				}
			}
			deleteFailed := false
			if len(deleteUIDs) > 0 {
				if actErr := applySpamActionBatch(c, deleteUIDs, "delete", trashMailbox); actErr != nil {
					log.Printf("apply batch delete in %s failed: %v", mailbox, actErr)
					deleteFailed = true
				}
			}

			var appliedIDs []int64
			var events []db.EmailEvent
			var abuseCandidates []abuse.Candidate
			for _, r := range chunk {
				actionTaken := r.Action
				if r.UIDValidity != mbox.UIDValidity {
					appliedIDs = append(appliedIDs, r.ID)
					continue
				}
				if actionTaken == "trash" && trashFailed && mailbox != trashMailbox {
					actionTaken = "error"
				} else if actionTaken == "delete" && deleteFailed {
					actionTaken = "error"
				}

				events = append(events, db.EmailEvent{
					Mailbox:      mailbox,
					UIDValidity:  r.UIDValidity,
					UID:          r.UID,
					MessageID:    r.MessageID,
					Sender:       r.Sender,
					SenderDomain: r.SenderDomain,
					Subject:      r.Subject,
					EmailDate:    r.EmailDate,
					CategoryID:   r.CategoryID,
					Confidence:   r.Confidence,
					Action:       actionTaken,
					Source:       "backfill",
				})

				if (actionTaken == "trash" || actionTaken == "delete") && r.RawHeaders != "" {
					if parsedDate, dErr := time.Parse(time.RFC3339, r.EmailDate); dErr == nil && wAgeWithin7Days(parsedDate) {
						abuseCandidates = append(abuseCandidates, abuse.Candidate{
							SenderEmail:  r.Sender,
							SenderDomain: r.SenderDomain,
							Subject:      r.Subject,
							RawHeaders:   r.RawHeaders,
							CategoryID:   r.CategoryID,
							Confidence:   r.Confidence,
							EmailDate:    parsedDate,
						})
					}
				}
				appliedIDs = append(appliedIDs, r.ID)
			}
			if err := s.store.RecordEmailEvents(events); err != nil {
				log.Printf("apply %s record events failed: %v", mailbox, err)
			}
			if s.abuseSvc != nil {
				for _, cand := range abuseCandidates {
					_ = s.abuseSvc.Consider(ctx, cand)
				}
			}
			_ = s.store.MarkScanResultsApplied(appliedIDs)
		}
	}

	job.CurrentMailbox = ""
	job.Status = "applied"
	_ = s.store.SaveScanJob(job)
	s.emit(job)
	_ = c.Logout().Wait()
}

func (s *Scanner) waitIfPaused(ctx context.Context) error {
	for s.isPaused() {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(250 * time.Millisecond):
		}
	}
	return ctx.Err()
}

func (s *Scanner) persist(job db.ScanJob) {
	_ = s.store.SaveScanJob(job)
	s.emit(job)
}

func (s *Scanner) failJob(job *db.ScanJob, err error) {
	job.Status = "failed"
	job.ErrorMsg = err.Error()
	_ = s.store.SaveScanJob(*job)
	s.emit(*job)
}

func (s *Scanner) emit(job db.ScanJob) {
	if s.OnProgress != nil {
		s.OnProgress(job)
	}
}

func buildSearchCriteria(dateRange string, now time.Time) *goimap.SearchCriteria {
	switch dateRange {
	case "30d":
		return &goimap.SearchCriteria{Since: now.AddDate(0, 0, -30)}
	case "1y":
		return &goimap.SearchCriteria{Since: now.AddDate(-1, 0, 0)}
	default:
		return &goimap.SearchCriteria{}
	}
}

func wAgeWithin7Days(emailDate time.Time) bool {
	if emailDate.IsZero() {
		return false
	}
	return time.Since(emailDate) <= 7*24*time.Hour
}

func cloneScanJob(j db.ScanJob) db.ScanJob {
	cp := j
	cp.Summary = make(map[string]int, len(j.Summary))
	for k, v := range j.Summary {
		cp.Summary[k] = v
	}
	cp.Checkpoints = make(map[string]uint32, len(j.Checkpoints))
	for k, v := range j.Checkpoints {
		cp.Checkpoints[k] = v
	}
	return cp
}
