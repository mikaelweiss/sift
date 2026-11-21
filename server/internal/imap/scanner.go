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
	"github.com/mikaelweiss/eclean/server/internal/abuse"
	"github.com/mikaelweiss/eclean/server/internal/classifier"
	"github.com/mikaelweiss/eclean/server/internal/db"
	"github.com/mikaelweiss/eclean/server/internal/jev"
)

const (
	maxDryRunSamples = 50
	scanBatchSize    = 50
	scanConcurrency  = jev.MaxConcurrentRequests
	scanWindow       = 4
	maxFetchBytes    = 65536
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
		Samples:     []db.ScanSample{},
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
	mailbox     string
	uidValidity uint32
	uids        []goimap.UID
}

type classifiedMsg struct {
	uid      goimap.UID
	input    classifier.EmailInput
	decision classifier.Decision
	err      error
}

type scanBatch struct {
	mailbox     string
	uidValidity uint32
	maxUID      uint32
	snap        *classifier.Snapshot
	msgs        []classifiedMsg
	done        sync.WaitGroup
}

type classifyTask struct {
	batch *scanBatch
	idx   int
}

// scanProgress guards the job shared by the IMAP loop and the classify workers.
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

// runJob keeps a single goroutine on the IMAP connection so fetches and moves never interleave,
// while a shared worker pool classifies several batches ahead of it.
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
	c, err := dialScanClient(cfg.IMAPHost, cfg.IMAPPort, cfg.IMAPUsername, cfg.IMAPPassword, nil)
	if err != nil {
		fail(err)
		return
	}
	defer c.Close()

	trashMailbox := discoverTrashMailbox(c)
	mailboxes := DiscoverMailboxes(c, true)
	criteria := buildSearchCriteria(job.DateRange, time.Now().UTC())

	var plans []folderPlan
	totalAcrossFolders := 0
	for _, mailbox := range mailboxes {
		if ctx.Err() != nil {
			markCancelled()
			return
		}
		mbox, selErr := c.Select(mailbox, &goimap.SelectOptions{ReadOnly: true}).Wait()
		if selErr != nil {
			log.Printf("scan skip folder %q: %v", mailbox, selErr)
			continue
		}
		searchData, searchErr := c.UIDSearch(criteria, nil).Wait()
		if searchErr != nil {
			log.Printf("scan search folder %q failed: %v", mailbox, searchErr)
			continue
		}
		allUIDs := searchData.AllUIDs()
		sort.Slice(allUIDs, func(i, j int) bool { return allUIDs[i] < allUIDs[j] })
		totalAcrossFolders += len(allUIDs)

		lastFolderUID := job.Checkpoints[mailbox]
		var pending []goimap.UID
		for _, u := range allUIDs {
			if uint32(u) > lastFolderUID {
				pending = append(pending, u)
			}
		}
		if len(pending) > 0 {
			plans = append(plans, folderPlan{
				mailbox:     mailbox,
				uidValidity: mbox.UIDValidity,
				uids:        pending,
			})
		}
	}

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

	for _, plan := range plans {
		if err := s.scanFolder(ctx, c, plan, job, trashMailbox, tasks, progress); err != nil {
			if ctx.Err() != nil {
				markCancelled()
			} else {
				fail(err)
			}
			return
		}
	}

	s.persist(progress.update(func(j *db.ScanJob) {
		j.CurrentMailbox = ""
		j.Status = "completed"
	}))
	_ = c.Logout().Wait()
}

func (s *Scanner) scanFolder(ctx context.Context, c *imapclient.Client, plan folderPlan, job db.ScanJob, trashMailbox string, tasks chan<- classifyTask, progress *scanProgress) error {
	s.persist(progress.update(func(j *db.ScanJob) { j.CurrentMailbox = plan.mailbox }))

	mbox, selErr := c.Select(plan.mailbox, &goimap.SelectOptions{ReadOnly: job.DryRun}).Wait()
	if selErr != nil {
		log.Printf("scan re-select %q failed: %v", plan.mailbox, selErr)
		return nil
	}

	var inFlight []*scanBatch
	for start := 0; start < len(plan.uids); start += scanBatchSize {
		if err := s.waitIfPaused(ctx); err != nil {
			return err
		}
		end := min(start+scanBatchSize, len(plan.uids))
		batch, err := s.fetchBatch(c, plan.mailbox, mbox.UIDValidity, plan.uids[start:end], job.DryRun, progress)
		if err != nil {
			return err
		}
		batch.done.Add(len(batch.msgs))
		for idx := range batch.msgs {
			select {
			case tasks <- classifyTask{batch: batch, idx: idx}:
			case <-ctx.Done():
				return ctx.Err()
			}
		}
		inFlight = append(inFlight, batch)
		if len(inFlight) >= scanWindow {
			if err := s.finishBatch(ctx, c, inFlight[0], job, trashMailbox, progress); err != nil {
				return err
			}
			inFlight = inFlight[1:]
		}
	}
	for _, batch := range inFlight {
		if err := s.finishBatch(ctx, c, batch, job, trashMailbox, progress); err != nil {
			return err
		}
	}
	return nil
}

func (s *Scanner) fetchBatch(c *imapclient.Client, mailbox string, uidValidity uint32, uids []goimap.UID, dryRun bool, progress *scanProgress) (*scanBatch, error) {
	snap, err := s.classifier.Snapshot()
	if err != nil {
		return nil, err
	}
	var fetchSet goimap.UIDSet
	for _, u := range uids {
		fetchSet.AddNum(u)
	}
	msgs, err := c.Fetch(fetchSet, &goimap.FetchOptions{
		UID:          true,
		InternalDate: true,
		BodySection:  []*goimap.FetchItemBodySection{scanBodySection},
	}).Collect()
	if err != nil {
		return nil, fmt.Errorf("fetch batch in %s: %w", mailbox, err)
	}

	batch := &scanBatch{mailbox: mailbox, uidValidity: uidValidity, snap: snap}
	alreadyProcessed := 0
	for _, msg := range msgs {
		uid := uint32(msg.UID)
		batch.maxUID = max(batch.maxUID, uid)
		if !dryRun {
			if exists, _ := s.store.HasEmailEvent(mailbox, uidValidity, uid); exists {
				alreadyProcessed++
				continue
			}
		}
		raw := extractBodyBytes(msg, scanBodySection)
		batch.msgs = append(batch.msgs, classifiedMsg{
			uid:   msg.UID,
			input: ParseRawMessage(uidValidity, uid, msg.InternalDate, raw),
		})
	}
	if alreadyProcessed > 0 {
		progress.update(func(j *db.ScanJob) { j.ScannedMessages += alreadyProcessed })
	}
	return batch, nil
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
		if len(job.Samples) < maxDryRunSamples {
			job.Samples = append(job.Samples, db.ScanSample{
				Mailbox:    t.batch.mailbox,
				UID:        uint32(msg.uid),
				Sender:     msg.input.SenderEmail,
				Subject:    msg.input.Subject,
				EmailDate:  msg.input.EmailDate.UTC().Format(time.RFC3339),
				CategoryID: dec.CategoryID,
				Confidence: dec.Confidence,
				Action:     dec.Action,
			})
		}
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

func (s *Scanner) finishBatch(ctx context.Context, c *imapclient.Client, b *scanBatch, job db.ScanJob, trashMailbox string, progress *scanProgress) error {
	b.done.Wait()
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if job.DryRun {
		s.recordDryRunBatch(job.ID, b)
	} else {
		s.applyBatch(ctx, c, b, trashMailbox)
	}
	s.persist(progress.update(func(j *db.ScanJob) {
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
		rawHdr := ""
		if (r.decision.Action == "trash" || r.decision.Action == "delete") && wAgeWithin7Days(r.input.EmailDate) {
			rawHdr = r.input.RawHeaders
		}
		rows = append(rows, db.ScanResult{
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
			Action:       r.decision.Action,
			RawHeaders:   rawHdr,
		})
	}
	if err := s.store.RecordScanResults(rows); err != nil {
		log.Printf("scan %s record dry run results failed: %v", b.mailbox, err)
	}
}

func (s *Scanner) applyBatch(ctx context.Context, c *imapclient.Client, b *scanBatch, trashMailbox string) {
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

	const applyChunkSize = 100
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

				_ = s.store.RecordEmailEvent(db.EmailEvent{
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

				if (actionTaken == "trash" || actionTaken == "delete") && r.RawHeaders != "" && s.abuseSvc != nil {
					if parsedDate, dErr := time.Parse(time.RFC3339, r.EmailDate); dErr == nil && wAgeWithin7Days(parsedDate) {
						_ = s.abuseSvc.Consider(ctx, abuse.Candidate{
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
	if len(j.Samples) > 0 {
		cp.Samples = append([]db.ScanSample(nil), j.Samples...)
	}
	return cp
}
