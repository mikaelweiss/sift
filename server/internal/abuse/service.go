package abuse

import (
	"context"
	"fmt"
	"time"

	"github.com/mikaelweiss/eclean/server/internal/db"
)

type Candidate struct {
	SenderEmail  string
	SenderDomain string
	Subject      string
	RawHeaders   string
	CategoryID   string
	Confidence   float64
	EmailDate    time.Time
}

type Service struct {
	store          *db.Store
	resolver       *Resolver
	sender         Sender
	nowFn          func() time.Time
	OnQueueChanged func(pendingCount int)
}

func NewService(store *db.Store, resolver *Resolver, sender Sender) *Service {
	if resolver == nil {
		resolver = NewResolver(store)
	}
	if sender == nil {
		sender = NewSMTPSender()
	}
	return &Service{
		store:    store,
		resolver: resolver,
		sender:   sender,
		nowFn:    func() time.Time { return time.Now().UTC() },
	}
}

func (s *Service) Consider(ctx context.Context, c Candidate) error {
	cfg, err := s.store.GetSettings()
	if err != nil {
		return err
	}
	if !cfg.AbuseEnabled {
		return nil
	}
	minConf := cfg.AbuseMinConfidence
	if minConf <= 0 {
		minConf = 0.95
	}
	if c.Confidence < minConf {
		return nil
	}
	if !c.EmailDate.IsZero() && s.nowFn().Sub(c.EmailDate) > 7*24*time.Hour {
		return nil
	}

	cats, err := s.store.ListCategories()
	if err != nil {
		return err
	}
	eligible := false
	for _, cat := range cats {
		if cat.ID == c.CategoryID && cat.AbuseEligible {
			eligible = true
			break
		}
	}
	if !eligible {
		return nil
	}

	rootDomain := RootDomain(c.SenderDomain)
	if rootDomain == "" {
		rootDomain = RootDomain(c.SenderEmail)
	}
	if rootDomain == "" {
		return nil
	}

	dismissed, err := s.store.IsAbuseDismissed(rootDomain)
	if err != nil || dismissed {
		return err
	}

	cooldownDays := cfg.AbuseCooldownDays
	if cooldownDays <= 0 {
		cooldownDays = 7
	}
	repeatOffense := false
	prevReportedAt := ""
	if lastTime, found, err := s.store.LastAbuseReportTime(rootDomain); err == nil && found {
		if s.nowFn().Sub(lastTime) < time.Duration(cooldownDays)*24*time.Hour {
			return nil
		}
		repeatOffense = true
		prevReportedAt = lastTime.Format(time.RFC3339)
	}

	sendingIP := ExtractOriginatingIP(c.RawHeaders)
	contacts, err := s.resolver.ResolveContacts(ctx, sendingIP, rootDomain)
	if err != nil || len(contacts) == 0 {
		return nil
	}

	redacted := RedactHeaders(c.RawHeaders, cfg.IMAPUsername, cfg.AbuseFromEmail)
	item, err := s.store.UpsertAbuseQueueItem(db.AbuseQueueItem{
		RootDomain:         rootDomain,
		SendingIP:          sendingIP,
		CategoryID:         c.CategoryID,
		Confidence:         c.Confidence,
		Targets:            contacts,
		RedactedHeaders:    redacted,
		Subject:            c.Subject,
		Sender:             c.SenderEmail,
		RepeatOffense:      repeatOffense,
		PreviousReportedAt: prevReportedAt,
	})
	if err != nil {
		return err
	}

	if !cfg.AbuseManualApproval {
		_, err = s.ApproveAndSend(ctx, item.ID)
		return err
	}
	s.notifyQueueChanged()
	return nil
}

func (s *Service) ApproveAndSend(ctx context.Context, queueID int64) (db.AbuseHistoryEntry, error) {
	item, err := s.store.GetAbuseQueueItem(queueID)
	if err != nil {
		return db.AbuseHistoryEntry{}, err
	}
	cfg, err := s.store.GetSettings()
	if err != nil {
		return db.AbuseHistoryEntry{}, err
	}

	subject, body := FormatReport(item)
	sendErr := s.sender.Send(ctx, cfg, item.Targets, subject, body)
	entry := db.AbuseHistoryEntry{
		RootDomain: item.RootDomain,
		SendingIP:  item.SendingIP,
		CategoryID: item.CategoryID,
		HitCount:   item.HitCount,
		Targets:    item.Targets,
		Status:     "sent",
		ReportedAt: s.nowFn().Format(time.RFC3339),
	}
	if sendErr != nil {
		entry.Status = "failed"
		entry.ErrorMsg = sendErr.Error()
		_ = s.store.RecordAbuseHistory(entry)
		return entry, sendErr
	}

	if err := s.store.RecordAbuseHistory(entry); err != nil {
		return entry, err
	}
	if err := s.store.DeleteAbuseQueueItem(queueID); err != nil {
		return entry, err
	}
	s.notifyQueueChanged()
	return entry, nil
}

func (s *Service) Dismiss(queueID int64) error {
	item, err := s.store.GetAbuseQueueItem(queueID)
	if err != nil {
		return err
	}
	if err := s.store.DismissAbuseDomain(item.RootDomain); err != nil {
		return err
	}
	s.notifyQueueChanged()
	return nil
}

func (s *Service) SendTest(ctx context.Context, toEmail string) error {
	cfg, err := s.store.GetSettings()
	if err != nil {
		return err
	}
	if toEmail == "" {
		toEmail = cfg.AbuseFromEmail
	}
	if toEmail == "" {
		return fmt.Errorf("recipient email is required")
	}
	return s.sender.Send(
		ctx,
		cfg,
		[]string{toEmail},
		"[EClean] Abuse reporting SMTP test",
		"This test message confirms EClean can deliver abuse reports using your configured SMTP settings.\n",
	)
}

func (s *Service) notifyQueueChanged() {
	if s.OnQueueChanged == nil {
		return
	}
	items, err := s.store.ListAbuseQueue()
	if err == nil {
		s.OnQueueChanged(len(items))
	}
}
