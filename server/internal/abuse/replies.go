package abuse

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"log"
	"regexp"
	"strings"
	"time"

	"github.com/mikaelweiss/sift/server/internal/db"
	"github.com/mikaelweiss/sift/server/internal/jev"
)

const (
	OutcomeActionTaken  = "action_taken"
	OutcomeFormOnly     = "form_only"
	OutcomeBounced      = "bounced"
	OutcomeAcknowledged = "acknowledged"
)

type ReplyInput struct {
	MessageID     string
	InReplyTo     string
	References    string
	From          string
	SenderEmail   string
	SenderDomain  string
	Subject       string
	BodySnippet   string
	AutoSubmitted string
	RawHeaders    string
	RawMessage    string
	EmailDate     time.Time
}

type replyCandidate struct {
	strongThread   bool
	isBounce       bool
	historyID      int64
	reportedDomain string
	targetAddress  string
}

var (
	angleIDRegex       = regexp.MustCompile(`<([^>\s]+)>`)
	bareMsgIDRegex     = regexp.MustCompile(`([^\s<>]+@[^\s<>]+)`)
	reportDomainRegex  = regexp.MustCompile(`(?i)\[(?:repeat\s+)?abuse report\][^\r\n]*?\bfrom\s+([a-z0-9.-]+\.[a-z]{2,})\b`)
	senderDomainLineRe = regexp.MustCompile(`(?im)^sender domain:\s*([a-z0-9.-]+\.[a-z]{2,})\b`)
	origRecipientRe    = regexp.MustCompile(`(?im)^original-recipient:\s*(?:rfc822;\s*)?([^\s<>]+@[^\s<>]+)`)
	quotedToLineRe     = regexp.MustCompile(`(?im)^to:\s*(?:[^<\r\n]*<)?([^\s<>]+@[^\s<>]+)>?`)
	diagCodeRe         = regexp.MustCompile(`(?im)^diagnostic-code:\s*(?:smtp;\s*)?(.+)$`)
	greetingLineRe     = regexp.MustCompile(`(?i)^(hello|hi|dear|hey|greetings|good\s+(morning|afternoon|evening))\b[^.!?]*[,!:]?$`)
	abuseTopicKeywords = []string{
		"abuse", "report", "ticket", "complaint", "phishing", "takedown", "suspend", "violation", "netcraft", "trust and safety",
	}
)

var replyQuestions = map[string]jev.NoulQuestion{
	"is_abuse_reply": {
		Type:         "noul",
		Instructions: "Is this email a reply, auto-response, ticket update, or status notification responding to an abuse or spam report submitted by the recipient?",
		Criteria: &jev.Criteria{
			True:  "The email is an acknowledgement, ticket update, investigation notice, web-form redirection, or enforcement outcome sent in response to a submitted abuse, phishing, or spam report.",
			False: "The email is a regular newsletter, personal message, marketing email, account notification, or unsolicited spam unrelated to a submitted abuse report.",
		},
	},
	"action_taken": {
		Type:         "noul",
		Instructions: "Does this reply confirm that the provider found a violation or already took enforcement action against the reported spammer, server, account, or domain?",
		Criteria: &jev.Criteria{
			True:  "The provider explicitly states they already took action, such as suspending or terminating an account or server, disabling or taking down a domain or site, blocking the sender, or finding a policy violation and taking appropriate action.",
			False: "The provider only acknowledges receipt, opens or closes a ticket, forwards the report to another team, redirects to a web form, or says they will review/investigate and take action if deemed necessary without confirming action was already taken.",
		},
	},
	"form_only": {
		Type:         "noul",
		Instructions: "Does this reply state that the provider does NOT accept or process abuse reports via email and requires submitting them through a web form instead?",
		Criteria: &jev.Criteria{
			True:  "The provider explicitly states they do not accept, monitor, or process abuse reports sent by email, or that only complaints submitted via their web form can be processed.",
			False: "The provider accepts and investigates the emailed report, even if they mention a web form as optional or for faster processing, or only reject an attachment format.",
		},
	},
}

// IsHeaderCandidate is a fast header-only pre-filter used by IMAP backfill syncs so full bodies
// are only fetched for messages that could be abuse report replies or bounces.
func IsHeaderCandidate(from, subject, inReplyTo, references, contentType string, knownTargetDomains map[string]struct{}, ownEmail string) bool {
	fromLower := strings.ToLower(strings.TrimSpace(from))
	if ownEmail != "" && strings.Contains(fromLower, strings.ToLower(strings.TrimSpace(ownEmail))) {
		return false
	}
	subjLower := strings.ToLower(subject)
	if strings.Contains(subjLower, "[abuse report]") || strings.Contains(subjLower, "[repeat abuse report]") {
		return true
	}
	if strings.Contains(strings.ToLower(inReplyTo+" "+references), "sift-abuse-") {
		return true
	}
	if isBounceHeader(fromLower, subjLower, strings.ToLower(contentType)) {
		return true
	}
	if containsAny(subjLower, "abuse claim", "reporting abuse", "aws abuse", "abuse report", "netcraft") {
		return true
	}
	_, domain := splitEmailDomain(fromLower)
	root := RootDomain(domain)
	if root == "" {
		return false
	}
	if root == "netcraft.com" {
		return true
	}
	if _, ok := formOnlyAbuseDomains[root]; ok {
		return true
	}
	if _, ok := knownTargetDomains[root]; ok && containsAny(subjLower, abuseTopicKeywords...) {
		return true
	}
	return false
}

// IsObviousAbuseReply catches abuse report replies synchronously without network calls,
// so historical scans never classify abuse replies as spam.
func IsObviousAbuseReply(subject, senderEmail, rawMessage string) bool {
	subjLower := strings.ToLower(subject)
	if strings.Contains(subjLower, "[abuse report]") || strings.Contains(subjLower, "[repeat abuse report]") {
		return true
	}
	if isBounceSender(strings.ToLower(senderEmail)) && rawReferencesSiftReport(rawMessage) {
		return true
	}
	return false
}

// KnownTargetRootDomains returns root domains of targets emailed recently plus learned form-only domains.
func (s *Service) KnownTargetRootDomains() map[string]struct{} {
	out := map[string]struct{}{"netcraft.com": {}}
	for d := range formOnlyAbuseDomains {
		out[d] = struct{}{}
	}
	if s == nil || s.store == nil {
		return out
	}
	if addrs, err := s.store.RecentAbuseTargetAddresses(90); err == nil {
		for _, a := range addrs {
			if r := RootDomain(a); r != "" {
				out[r] = struct{}{}
			}
		}
	}
	if learned, err := s.store.ListFormOnlyAbuseDomains(); err == nil {
		for _, d := range learned {
			out[d] = struct{}{}
		}
	}
	return out
}

// HandleIncoming checks whether an inbound message is a reply or bounce from an abuse report,
// classifies it with Jev, records any confirmed ban or learned form-only desk, and returns handled=true
// when the caller should archive the message instead of running spam filtering.
func (s *Service) HandleIncoming(ctx context.Context, in ReplyInput) (bool, *db.AbuseReply, error) {
	if s == nil || s.store == nil {
		return false, nil, nil
	}
	cfg, err := s.store.GetSettings()
	if err != nil {
		return false, nil, err
	}
	own := strings.ToLower(strings.TrimSpace(cfg.IMAPUsername))
	if own != "" && strings.EqualFold(strings.TrimSpace(in.SenderEmail), own) {
		return false, nil, nil
	}

	cand, matched := s.matchCandidate(in)
	if !matched {
		return false, nil, nil
	}

	msgKey := replyMessageKey(in)
	if seen, err := s.store.HasAbuseReply(msgKey); err == nil && seen {
		return true, nil, nil
	}

	cleaned := cleanReplyBody(in.BodySnippet)
	outcome := OutcomeAcknowledged
	snippet := extractDisplaySnippet(cleaned)

	if cand.isBounce {
		outcome = OutcomeBounced
		if diag := extractBounceDiagnostic(in.RawMessage); diag != "" {
			snippet = diag
		}
	} else {
		eval := s.replyEvaluator(cfg)
		if eval == nil {
			if !cand.strongThread && !subjectHasAbuseTag(in.Subject) {
				return false, nil, nil
			}
		} else {
			state := map[string]any{
				"from":           in.From,
				"sender_domain":  in.SenderDomain,
				"subject":        in.Subject,
				"auto_submitted": in.AutoSubmitted,
				"body_snippet":   truncateString(cleaned, 2500),
			}
			scores, err := eval.EvaluateNoul(ctx, state, replyQuestions)
			if err != nil {
				return false, nil, err
			}
			minReply := 0.70
			if cand.strongThread || subjectHasAbuseTag(in.Subject) {
				minReply = 0.50
			}
			if scores["is_abuse_reply"] < minReply {
				return false, nil, nil
			}
			switch {
			case scores["action_taken"] >= 0.75:
				outcome = OutcomeActionTaken
			case scores["form_only"] >= 0.80:
				outcome = OutcomeFormOnly
			default:
				outcome = OutcomeAcknowledged
			}
		}
	}

	responderDomain := RootDomain(in.SenderDomain)
	if responderDomain == "" {
		responderDomain = RootDomain(in.SenderEmail)
	}
	if cand.targetAddress == "" {
		cand.targetAddress = s.inferTargetAddress(in, cand.reportedDomain, responderDomain)
	}
	if cand.historyID == 0 && cand.reportedDomain != "" {
		if hID, _, found, err := s.store.FindLatestAbuseHistoryByDomain(cand.reportedDomain); err == nil && found {
			cand.historyID = hID
		}
	}

	receivedAt := in.EmailDate
	if receivedAt.IsZero() {
		receivedAt = s.nowFn()
	}

	reply := db.AbuseReply{
		MessageID:       msgKey,
		ReportedDomain:  cand.reportedDomain,
		HistoryID:       cand.historyID,
		Responder:       in.SenderEmail,
		ResponderDomain: responderDomain,
		TargetAddress:   cand.targetAddress,
		Subject:         in.Subject,
		Snippet:         snippet,
		Outcome:         outcome,
		ReceivedAt:      receivedAt.UTC().Format(time.RFC3339),
	}

	inserted, err := s.store.RecordAbuseReply(reply)
	if err != nil {
		return false, nil, err
	}

	if outcome == OutcomeFormOnly {
		s.learnFormOnlyDomains(responderDomain, cand.targetAddress)
	}
	if inserted && outcome == OutcomeActionTaken && s.OnBanRecorded != nil {
		if count, err := s.store.CountAbuseBans(); err == nil {
			s.OnBanRecorded(count)
		}
	}
	return true, &reply, nil
}

func (s *Service) replyEvaluator(cfg db.AppSettings) jev.Evaluator {
	if s.evaluator != nil {
		return s.evaluator
	}
	if cfg.AIAPIKey == "" {
		return nil
	}
	return jev.NewClient(cfg.AIProvider, cfg.AIAPIKey, cfg.AIModel)
}

func (s *Service) matchCandidate(in ReplyInput) (replyCandidate, bool) {
	var cand replyCandidate

	threadIDs := extractMessageIDs(in.InReplyTo + " " + in.References)
	if len(threadIDs) > 0 {
		if hID, dom, target, found, err := s.store.FindAbuseDeliveryByMessageID(threadIDs); err == nil && found {
			cand.strongThread = true
			cand.historyID = hID
			cand.reportedDomain = dom
			cand.targetAddress = target
		} else {
			for _, id := range threadIDs {
				if strings.Contains(strings.ToLower(id), "sift-abuse-") {
					cand.strongThread = true
					break
				}
			}
		}
	}

	// Check DSN bounces (e.g. mailer-daemon@icloud.com returning an outbound abuse report).
	if isBounceHeader(strings.ToLower(in.SenderEmail), strings.ToLower(in.Subject), strings.ToLower(in.RawHeaders)) {
		if s.bounceMatchesSiftReport(in, &cand) {
			cand.isBounce = true
			if cand.reportedDomain == "" {
				cand.reportedDomain = extractReportedDomain(in.Subject, in.BodySnippet, in.RawMessage)
			}
			return cand, true
		}
		return replyCandidate{}, false
	}

	if cand.reportedDomain == "" {
		cand.reportedDomain = extractReportedDomain(in.Subject, in.BodySnippet, in.RawMessage)
	}

	if cand.strongThread || subjectHasAbuseTag(in.Subject) {
		return cand, true
	}

	bodyAndRaw := strings.ToLower(in.BodySnippet + "\n" + in.RawMessage)
	if strings.Contains(bodyAndRaw, "[abuse report]") || strings.Contains(bodyAndRaw, "[repeat abuse report]") {
		return cand, true
	}

	senderRoot := RootDomain(in.SenderDomain)
	if senderRoot == "" {
		senderRoot = RootDomain(in.SenderEmail)
	}
	if senderRoot != "" {
		known := s.KnownTargetRootDomains()
		if _, ok := known[senderRoot]; ok {
			if containsAny(strings.ToLower(in.Subject+" "+in.BodySnippet), abuseTopicKeywords...) {
				return cand, true
			}
		}
	}

	return replyCandidate{}, false
}

func (s *Service) bounceMatchesSiftReport(in ReplyInput, cand *replyCandidate) bool {
	if cand.strongThread {
		return true
	}
	if rawReferencesSiftReport(in.RawMessage) {
		if m := origRecipientRe.FindStringSubmatch(in.RawMessage); len(m) == 2 {
			cand.targetAddress = strings.ToLower(strings.TrimSpace(m[1]))
		} else if m := quotedToLineRe.FindStringSubmatch(in.RawMessage); len(m) == 2 {
			cand.targetAddress = strings.ToLower(strings.TrimSpace(m[1]))
		}
		return true
	}
	// Match stored delivery Message-IDs embedded in bounce headers.
	rawIDs := extractMessageIDs(in.RawMessage)
	if len(rawIDs) > 0 {
		if hID, dom, target, found, err := s.store.FindAbuseDeliveryByMessageID(rawIDs); err == nil && found {
			cand.historyID = hID
			cand.reportedDomain = dom
			cand.targetAddress = target
			return true
		}
	}
	return false
}

func (s *Service) inferTargetAddress(in ReplyInput, reportedDomain, responderRoot string) string {
	// Look for quoted "To: <addr>" from the original report inside the reply body.
	for _, m := range quotedToLineRe.FindAllStringSubmatch(in.BodySnippet, 4) {
		addr := strings.ToLower(strings.TrimSpace(m[1]))
		if isValidEmail(addr) && !strings.EqualFold(addr, in.SenderEmail) {
			if _, ok := icloudDomains[RootDomain(addr)]; !ok {
				return addr
			}
		}
	}
	if reportedDomain != "" {
		if _, deliveries, found, err := s.store.FindLatestAbuseHistoryByDomain(reportedDomain); err == nil && found {
			var emailDeliveries []db.AbuseDelivery
			for _, d := range deliveries {
				if d.Kind != KindNetcraft && d.Address != "" {
					if RootDomain(d.Address) == responderRoot {
						return d.Address
					}
					emailDeliveries = append(emailDeliveries, d)
				}
			}
			if len(emailDeliveries) == 1 {
				return emailDeliveries[0].Address
			}
		}
	}
	return ""
}

func (s *Service) learnFormOnlyDomains(responderRoot, targetAddress string) {
	learn := func(dom string) {
		root := RootDomain(dom)
		if root == "" || IsSharedMailProvider(root) || isAWSTrustSafety("a@"+root) || root == "amazon.com" || root == "netcraft.com" {
			return
		}
		if err := s.store.AddFormOnlyAbuseDomain(root, "learned"); err != nil {
			log.Printf("abuse: save learned form-only domain %s: %v", root, err)
		}
	}
	if targetAddress != "" {
		learn(targetAddress)
	}
	if responderRoot != "" {
		learn(responderRoot)
	}
}

func subjectHasAbuseTag(subject string) bool {
	lower := strings.ToLower(subject)
	return strings.Contains(lower, "[abuse report]") || strings.Contains(lower, "[repeat abuse report]")
}

func rawReferencesSiftReport(raw string) bool {
	lower := strings.ToLower(raw)
	return strings.Contains(lower, "[abuse report]") ||
		strings.Contains(lower, "[repeat abuse report]") ||
		strings.Contains(lower, "sift-abuse-") ||
		strings.Contains(lower, `boundary="sift-`)
}

func isBounceSender(senderLower string) bool {
	return strings.HasPrefix(senderLower, "mailer-daemon@") ||
		strings.HasPrefix(senderLower, "postmaster@") ||
		strings.Contains(senderLower, "<mailer-daemon@") ||
		strings.Contains(senderLower, "<postmaster@")
}

func isBounceHeader(fromLower, subjLower, headersOrCTLower string) bool {
	if isBounceSender(fromLower) {
		return true
	}
	if strings.Contains(headersOrCTLower, "multipart/report") && strings.Contains(headersOrCTLower, "delivery-status") {
		return true
	}
	return strings.Contains(subjLower, "undelivered mail returned to sender") ||
		strings.Contains(subjLower, "delivery status notification") ||
		strings.Contains(subjLower, "mail delivery failed")
}

func extractMessageIDs(s string) []string {
	var out []string
	seen := map[string]struct{}{}
	add := func(id string) {
		norm := db.NormalizeMessageID(id)
		if norm == "" {
			return
		}
		if _, ok := seen[norm]; ok {
			return
		}
		seen[norm] = struct{}{}
		out = append(out, norm)
	}
	for _, m := range angleIDRegex.FindAllStringSubmatch(s, -1) {
		add(m[1])
	}
	if len(out) == 0 {
		for _, m := range bareMsgIDRegex.FindAllStringSubmatch(s, -1) {
			add(m[1])
		}
	}
	return out
}

func extractReportedDomain(subject, body, raw string) string {
	for _, text := range []string{subject, body, raw} {
		if m := reportDomainRegex.FindStringSubmatch(text); len(m) == 2 {
			return RootDomain(m[1])
		}
	}
	for _, text := range []string{body, raw} {
		if m := senderDomainLineRe.FindStringSubmatch(text); len(m) == 2 {
			return RootDomain(m[1])
		}
	}
	return ""
}

func cleanReplyBody(body string) string {
	normalized := strings.ReplaceAll(body, "\r\n", "\n")
	separators := []string{
		"-----Original Message-----",
		"--------------- Original Message ---------------",
		"Your original report:",
		"Full headers:",
		"________________________________",
	}
	for _, sep := range separators {
		if idx := strings.Index(normalized, sep); idx >= 0 {
			normalized = normalized[:idx]
		}
	}
	return strings.TrimSpace(normalized)
}

func extractDisplaySnippet(cleaned string) string {
	var kept []string
	for _, rawLine := range strings.Split(cleaned, "\n") {
		line := strings.TrimSpace(rawLine)
		if line == "" || strings.HasPrefix(line, "---") || strings.HasPrefix(line, "===") {
			continue
		}
		if len(kept) == 0 && greetingLineRe.MatchString(line) {
			continue
		}
		lower := strings.ToLower(line)
		if strings.HasPrefix(lower, "thank you for bringing this to our attention") ||
			strings.HasPrefix(lower, "thank you for letting us know") ||
			strings.HasPrefix(lower, "thank you for contacting") ||
			strings.HasPrefix(lower, "thank you for submitting") {
			if len(kept) == 0 {
				continue
			}
		}
		kept = append(kept, line)
		if len(strings.Join(kept, " ")) >= 200 || len(kept) >= 2 {
			break
		}
	}
	if len(kept) == 0 {
		return truncateString(strings.Join(strings.Fields(cleaned), " "), 220)
	}
	return truncateString(strings.Join(kept, " "), 220)
}

func extractBounceDiagnostic(raw string) string {
	if m := diagCodeRe.FindStringSubmatch(raw); len(m) == 2 {
		return truncateString(strings.TrimSpace(m[1]), 220)
	}
	return "Delivery bounced by mail server"
}

func replyMessageKey(in ReplyInput) string {
	if norm := db.NormalizeMessageID(in.MessageID); norm != "" {
		return norm
	}
	sum := sha256.Sum256([]byte(strings.ToLower(in.SenderEmail) + "|" + in.Subject + "|" + in.EmailDate.UTC().Format(time.RFC3339)))
	return "hash:" + hex.EncodeToString(sum[:16])
}

func splitEmailDomain(from string) (string, string) {
	if m := angleAddr.FindStringSubmatch(from); len(m) == 2 {
		return "", strings.TrimSpace(m[1])
	}
	if _, d, ok := strings.Cut(from, "@"); ok {
		return "", strings.Trim(strings.Fields(d)[0], "<>.,;\"'")
	}
	return "", ""
}

func containsAny(s string, needles ...string) bool {
	for _, n := range needles {
		if strings.Contains(s, n) {
			return true
		}
	}
	return false
}

func truncateString(s string, maxLen int) string {
	s = strings.TrimSpace(s)
	if len(s) <= maxLen {
		return s
	}
	return strings.TrimSpace(s[:maxLen-1]) + "..."
}
