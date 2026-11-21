package abuse

import (
	"context"
	"errors"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/mikaelweiss/sift/server/internal/db"
)

type Candidate struct {
	SenderEmail  string
	SenderDomain string
	From         string
	Subject      string
	RawMessage   string
	LinkDomains  []string
	CategoryID   string
	Confidence   float64
	EmailDate    time.Time
}

const deliveryTimeout = 10 * time.Minute

type Service struct {
	store          *db.Store
	resolver       *Resolver
	sender         Sender
	netcraft       func(ctx context.Context, reporterEmail, message string) error
	nowFn          func() time.Time
	sending        sync.WaitGroup
	OnQueueChanged func(pendingCount int)
}

func NewService(store *db.Store, resolver *Resolver, sender Sender) *Service {
	if resolver == nil {
		resolver = NewResolver(store)
	}
	if sender == nil {
		sender = NewSMTPSender()
	}
	// A restart mid-delivery leaves items marked sending. Returning them to the queue lets the user approve again.
	if err := store.ReleaseSendingAbuseQueue(); err != nil {
		log.Printf("abuse: release interrupted reports: %v", err)
	}
	return &Service{
		store:    store,
		resolver: resolver,
		sender:   sender,
		netcraft: newNetcraftReporter().Report,
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

	headers := headerBlock(c.RawMessage)
	sendingIP := ExtractOriginatingIP(headers)
	targets := s.resolver.ResolveTargets(ctx, c, headers, sendingIP, rootDomain)
	if len(targets) == 0 {
		return nil
	}

	item, err := s.store.UpsertAbuseQueueItem(db.AbuseQueueItem{
		RootDomain:         rootDomain,
		SendingIP:          sendingIP,
		CategoryID:         c.CategoryID,
		Confidence:         c.Confidence,
		Targets:            targets,
		RedactedHeaders:    RedactHeaders(headers, cfg.IMAPUsername),
		Evidence:           RedactHeaders(c.RawMessage, cfg.IMAPUsername),
		Subject:            c.Subject,
		Sender:             c.SenderEmail,
		RepeatOffense:      repeatOffense,
		PreviousReportedAt: prevReportedAt,
	})
	if err != nil {
		return err
	}

	if !cfg.AbuseManualApproval && item.Status == "pending" {
		return s.Approve(item.ID)
	}
	s.notifyQueueChanged()
	return nil
}

// Approve marks the report as sending and delivers it in the background.
func (s *Service) Approve(queueID int64) error {
	claimed, err := s.store.ClaimAbuseQueueItem(queueID)
	if err != nil {
		return err
	}
	if !claimed {
		return errors.New("this report is already sending or no longer queued")
	}
	s.notifyQueueChanged()
	s.sending.Add(1)
	go func() {
		defer s.sending.Done()
		s.deliver(queueID)
	}()
	return nil
}

// WaitForDeliveries blocks until every background delivery has finished.
func (s *Service) WaitForDeliveries() {
	s.sending.Wait()
}

func (s *Service) deliver(queueID int64) {
	ctx, cancel := context.WithTimeout(context.Background(), deliveryTimeout)
	defer cancel()
	defer s.notifyQueueChanged()

	item, err := s.store.GetAbuseQueueItem(queueID)
	if err != nil {
		log.Printf("abuse: load report %d: %v", queueID, err)
		return
	}
	cfg, err := s.store.GetSettings()
	if err != nil {
		log.Printf("abuse: load settings: %v", err)
		_ = s.store.ReleaseAbuseQueueItem(queueID)
		return
	}

	deliveries := make([]db.AbuseDelivery, 0, len(item.Targets))
	for _, target := range item.Targets {
		var sendErr error
		if target.Kind == KindNetcraft {
			sendErr = s.netcraft(ctx, cfg.IMAPUsername, item.Evidence)
		} else {
			subject, body := FormatReport(item, target)
			sendErr = s.sender.Send(ctx, cfg, Mail{
				To:             target.Address,
				Subject:        subject,
				Body:           body,
				Attachment:     []byte(item.Evidence),
				AttachmentName: "evidence.eml",
			})
		}
		d := db.AbuseDelivery{AbuseTarget: target, OK: sendErr == nil}
		if sendErr != nil {
			d.Error = sendErr.Error()
		}
		deliveries = append(deliveries, d)
	}

	status := deliveryStatus(deliveries)
	if err := s.store.RecordAbuseHistory(db.AbuseHistoryEntry{
		RootDomain: item.RootDomain,
		SendingIP:  item.SendingIP,
		CategoryID: item.CategoryID,
		HitCount:   item.HitCount,
		Subject:    item.Subject,
		Sender:     item.Sender,
		Deliveries: deliveries,
		Status:     status,
		ReportedAt: s.nowFn().Format(time.RFC3339),
	}); err != nil {
		log.Printf("abuse: record history for %s: %v", item.RootDomain, err)
	}
	if status == "failed" {
		_ = s.store.ReleaseAbuseQueueItem(queueID)
		return
	}
	_ = s.store.DeleteAbuseQueueItem(queueID)
}

func deliveryStatus(deliveries []db.AbuseDelivery) string {
	ok := 0
	for _, d := range deliveries {
		if d.OK {
			ok++
		}
	}
	switch {
	case ok == len(deliveries) && ok > 0:
		return "sent"
	case ok == 0:
		return "failed"
	default:
		return "partial"
	}
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

func (s *Service) notifyQueueChanged() {
	if s.OnQueueChanged == nil {
		return
	}
	items, err := s.store.ListAbuseQueue()
	if err == nil {
		s.OnQueueChanged(len(items))
	}
}

func headerBlock(raw string) string {
	normalized := strings.ReplaceAll(raw, "\r\n", "\n")
	if i := strings.Index(normalized, "\n\n"); i >= 0 {
		return normalized[:i]
	}
	return normalized
}

var categoryLabels = map[string]string{
	"phishing_scams":  "Phishing / scam",
	"crypto_gambling": "Crypto / gambling scam",
	"adult_explicit":  "Unsolicited adult content",
}

func FormatReport(item db.AbuseQueueItem, target db.AbuseTarget) (subject, body string) {
	label := categoryLabels[item.CategoryID]
	if label == "" {
		label = "Unsolicited bulk email"
	}
	prefix := "Abuse Report"
	if item.RepeatOffense {
		prefix = "Repeat Abuse Report"
	}
	subject = fmt.Sprintf("[%s] %s from %s", prefix, label, item.RootDomain)

	var b strings.Builder
	b.WriteString("Hello,\n\n")
	b.WriteString(fmt.Sprintf("I am reporting an unsolicited email. You are receiving this report because: %s.\n\n", target.Reason))
	b.WriteString(fmt.Sprintf("Sender: %s\n", item.Sender))
	b.WriteString(fmt.Sprintf("Sender domain: %s\n", item.RootDomain))
	if item.SendingIP != "" {
		b.WriteString(fmt.Sprintf("Originating IP: %s\n", item.SendingIP))
	}
	b.WriteString(fmt.Sprintf("Subject: %s\n", item.Subject))
	b.WriteString(fmt.Sprintf("Type: %s\n", label))
	b.WriteString(fmt.Sprintf("Messages received: %d\n", item.HitCount))
	if item.RepeatOffense && item.PreviousReportedAt != "" {
		b.WriteString(fmt.Sprintf("Previously reported: %s\n", item.PreviousReportedAt))
	}
	b.WriteString("\nThe original message is attached as evidence.eml with my address removed. ")
	b.WriteString("It holds the full headers and the first 64 KB of the message; attachments are not included.\n\n")
	b.WriteString("Full headers:\n")
	b.WriteString("------------------------------------------------------------\n")
	b.WriteString(item.RedactedHeaders)
	b.WriteString("\n------------------------------------------------------------\n")
	return subject, b.String()
}
