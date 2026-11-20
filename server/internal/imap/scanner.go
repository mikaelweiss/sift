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
	"github.com/google/uuid"
	"github.com/mikaelweiss/eclean/server/internal/abuse"
	"github.com/mikaelweiss/eclean/server/internal/classifier"
	"github.com/mikaelweiss/eclean/server/internal/db"
)

const (
	maxDryRunSamples = 50
	scanBatchSize    = 25
)

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
	if ratePerSec <= 0 || ratePerSec > 20 {
		ratePerSec = 5
	}
	job := db.ScanJob{
		ID:         uuid.NewString(),
		DateRange:  dateRange,
		DryRun:     dryRun,
		RatePerSec: ratePerSec,
		Status:     "running",
		Summary:    map[string]int{},
		Samples:    []db.ScanSample{},
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

func (s *Scanner) runJob(ctx context.Context, job db.ScanJob) {
	defer s.clearActive(job.ID)

	cfg, err := s.store.GetSettings()
	if err != nil {
		s.failJob(&job, err)
		return
	}
	c, err := dialAndLogin(cfg.IMAPHost, cfg.IMAPPort, cfg.IMAPUsername, cfg.IMAPPassword, nil)
	if err != nil {
		s.failJob(&job, err)
		return
	}
	defer c.Close()

	trashMailbox := discoverTrashMailbox(c)
	mbox, err := c.Select("INBOX", &goimap.SelectOptions{ReadOnly: job.DryRun}).Wait()
	if err != nil {
		s.failJob(&job, fmt.Errorf("select INBOX: %w", err))
		return
	}

	criteria := buildSearchCriteria(job.DateRange, time.Now().UTC())
	searchData, err := c.UIDSearch(criteria, nil).Wait()
	if err != nil {
		s.failJob(&job, fmt.Errorf("search INBOX: %w", err))
		return
	}

	allUIDs := searchData.AllUIDs()
	sort.Slice(allUIDs, func(i, j int) bool { return allUIDs[i] < allUIDs[j] })

	var pending []goimap.UID
	for _, u := range allUIDs {
		if uint32(u) > job.LastUID {
			pending = append(pending, u)
		}
	}
	if job.TotalMessages == 0 {
		job.TotalMessages = len(allUIDs)
		_ = s.store.SaveScanJob(job)
		s.emit(job)
	}

	minDelay := time.Duration(float64(time.Second) / job.RatePerSec)
	bodySection := &goimap.FetchItemBodySection{Peek: true}

	for start := 0; start < len(pending); start += scanBatchSize {
		if err := s.waitIfPaused(ctx); err != nil {
			job.Status = "cancelled"
			_ = s.store.SaveScanJob(job)
			s.emit(job)
			return
		}

		end := start + scanBatchSize
		if end > len(pending) {
			end = len(pending)
		}
		var fetchSet goimap.UIDSet
		for _, u := range pending[start:end] {
			fetchSet.AddNum(u)
		}

		msgs, err := c.Fetch(fetchSet, &goimap.FetchOptions{
			UID:          true,
			InternalDate: true,
			BodySection:  []*goimap.FetchItemBodySection{bodySection},
		}).Collect()
		if err != nil {
			s.failJob(&job, fmt.Errorf("fetch batch: %w", err))
			return
		}

		for _, msg := range msgs {
			if err := s.waitIfPaused(ctx); err != nil {
				job.Status = "cancelled"
				_ = s.store.SaveScanJob(job)
				s.emit(job)
				return
			}

			uid := uint32(msg.UID)
			if !job.DryRun {
				if exists, _ := s.store.HasEmailEvent(mbox.UIDValidity, uid); exists {
					job.ScannedMessages++
					job.LastUID = uid
					continue
				}
			}

			raw := msg.FindBodySection(bodySection)
			input := ParseRawMessage(mbox.UIDValidity, uid, msg.InternalDate, raw)
			decision, evalErr := s.classifier.Evaluate(ctx, input)
			if evalErr != nil {
				log.Printf("scan UID %d classify failed: %v", uid, evalErr)
				job.ScannedMessages++
				job.LastUID = uid
				continue
			}

			isSpam := decision.Action == "trash" || decision.Action == "delete"
			if isSpam {
				job.SpamFound++
				if job.Summary == nil {
					job.Summary = map[string]int{}
				}
				job.Summary[decision.CategoryID]++
				if len(job.Samples) < maxDryRunSamples {
					job.Samples = append(job.Samples, db.ScanSample{
						UID:        uid,
						Sender:     input.SenderEmail,
						Subject:    input.Subject,
						EmailDate:  input.EmailDate.UTC().Format(time.RFC3339),
						CategoryID: decision.CategoryID,
						Confidence: decision.Confidence,
						Action:     decision.Action,
					})
				}
			}

			if !job.DryRun {
				actionTaken := decision.Action
				if isSpam {
					if actErr := applySpamAction(c, msg.UID, decision.Action, trashMailbox); actErr != nil {
						log.Printf("scan apply %s UID %d failed: %v", decision.Action, uid, actErr)
						actionTaken = "error"
					}
				}
				_ = s.store.RecordEmailEvent(db.EmailEvent{
					UIDValidity:  mbox.UIDValidity,
					UID:          uid,
					MessageID:    input.MessageID,
					Sender:       input.SenderEmail,
					SenderDomain: input.SenderDomain,
					Subject:      input.Subject,
					EmailDate:    input.EmailDate.UTC().Format(time.RFC3339),
					CategoryID:   decision.CategoryID,
					Confidence:   decision.Confidence,
					Action:       actionTaken,
					Source:       "backfill",
				})
				// Only consider abuse reporting for emails newer than 7 days.
				if (actionTaken == "trash" || actionTaken == "delete") && wAgeWithin7Days(input.EmailDate) && s.abuseSvc != nil {
					_ = s.abuseSvc.Consider(ctx, abuse.Candidate{
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

			job.ScannedMessages++
			job.LastUID = uid
			_ = s.store.SaveScanJob(job)
			s.emit(job)

			select {
			case <-ctx.Done():
				job.Status = "cancelled"
				_ = s.store.SaveScanJob(job)
				s.emit(job)
				return
			case <-time.After(minDelay):
			}
		}
	}

	job.Status = "completed"
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
