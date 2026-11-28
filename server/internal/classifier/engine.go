package classifier

import (
	"context"
	"fmt"
	"net/mail"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/mikaelweiss/sift/server/internal/db"
	"github.com/mikaelweiss/sift/server/internal/jev"
)

const maxBodySnippetLen = 2500

var urlRegex = regexp.MustCompile(`https?://[^\s"'<>()]+`)

type EmailInput struct {
	UIDValidity   uint32
	UID           uint32
	MessageID     string
	InReplyTo     string
	References    string
	AutoSubmitted string
	From          string
	ReplyTo       string
	SenderEmail   string
	SenderDomain  string
	Subject       string
	AuthResults   string
	LinkDomains   []string
	BodySnippet   string
	EmailDate     time.Time
	RawHeaders    string
	// RawMessage is the fetched message prefix kept as report evidence.
	RawMessage     string
	DMARCPass      bool
	UnsubscribeURL string
}

type Decision struct {
	Action       string
	CategoryID   string
	CategoryName string
	Confidence   float64
	Allowlisted  bool
	// AbuseEligible marks the top category as one that warrants abuse reports.
	AbuseEligible bool
	Scores        map[string]float64
}

type Engine struct {
	store     *db.Store
	evaluator jev.Evaluator
}

// Snapshot holds preloaded settings, categories, allowlist, and a reusable Jev client for concurrent batch evaluation.
type Snapshot struct {
	cfg       db.AppSettings
	questions map[string]jev.NoulQuestion
	catByID   map[string]db.Category
	allowlist []db.AllowlistEntry
	eval      jev.Evaluator
}

func NewEngine(store *db.Store, evaluator jev.Evaluator) *Engine {
	return &Engine{store: store, evaluator: evaluator}
}

func (e *Engine) Snapshot() (*Snapshot, error) {
	cfg, err := e.store.GetSettings()
	if err != nil {
		return nil, fmt.Errorf("load settings: %w", err)
	}
	cats, err := e.store.ListCategories()
	if err != nil {
		return nil, fmt.Errorf("load categories: %w", err)
	}
	allowlist, err := e.store.ListAllowlist()
	if err != nil {
		return nil, fmt.Errorf("load allowlist: %w", err)
	}

	questions := make(map[string]jev.NoulQuestion)
	catByID := make(map[string]db.Category)
	for _, c := range cats {
		if !c.Enabled {
			continue
		}
		catByID[c.ID] = c
		questions[c.ID] = jev.NoulQuestion{
			Type: "noul",
			Instructions: fmt.Sprintf(
				"Does this incoming email belong to the blocked spam category %q (%s)?",
				c.Name, c.Description,
			),
			Criteria: &jev.Criteria{
				True:  fmt.Sprintf("The email clearly matches %s and is unwanted spam, bulk promotion, or unsolicited outreach.", c.Name),
				False: "The email is personal, transactional, security/auth, receipt/billing, or an onboarding, welcome, or account/subscription setup email for a service the recipient signed up for, or does not match this category.",
			},
		}
	}

	eval := e.evaluator
	if eval == nil && cfg.AIAPIKey != "" {
		eval = jev.NewClient(cfg.AIProvider, cfg.AIAPIKey, cfg.AIModel)
	}

	return &Snapshot{
		cfg:       cfg,
		questions: questions,
		catByID:   catByID,
		allowlist: allowlist,
		eval:      eval,
	}, nil
}

func (e *Engine) Evaluate(ctx context.Context, in EmailInput) (Decision, error) {
	snap, err := e.Snapshot()
	if err != nil {
		return Decision{}, err
	}
	return snap.Evaluate(ctx, in)
}

func (s *Snapshot) Evaluate(ctx context.Context, in EmailInput) (Decision, error) {
	senderEmail, senderDomain := in.SenderEmail, in.SenderDomain
	if senderEmail == "" || senderDomain == "" {
		parsedEmail, parsedDomain := ParseSenderAddress(in.From)
		if senderEmail == "" {
			senderEmail = parsedEmail
		}
		if senderDomain == "" {
			senderDomain = parsedDomain
		}
	}

	if s.isAllowlisted(senderEmail, senderDomain, in.DMARCPass) || s.isOwnAddress(senderEmail) {
		return Decision{Action: "keep", Allowlisted: true}, nil
	}
	if len(s.questions) == 0 || s.eval == nil {
		return Decision{Action: "keep"}, nil
	}

	snippet := in.BodySnippet
	if len(snippet) > maxBodySnippetLen {
		snippet = snippet[:maxBodySnippetLen]
	}

	state := map[string]any{
		"from":                   in.From,
		"reply_to":               in.ReplyTo,
		"sender_domain":          senderDomain,
		"subject":                in.Subject,
		"authentication_results": in.AuthResults,
		"link_domains":           in.LinkDomains,
		"body_snippet":           snippet,
	}

	scores, err := s.eval.EvaluateNoul(ctx, state, s.questions)
	if err != nil {
		return Decision{}, err
	}

	var topID string
	var topScore float64
	for id, score := range scores {
		if score > topScore {
			topScore = score
			topID = id
		}
	}

	dec := Decision{
		Action:     "keep",
		CategoryID: topID,
		Confidence: topScore,
		Scores:     scores,
	}
	if c, ok := s.catByID[topID]; ok {
		dec.CategoryName = c.Name
		dec.AbuseEligible = c.AbuseEligible
	}

	junkThreshold := s.cfg.JunkThreshold
	if junkThreshold <= 0 {
		junkThreshold = 0.85
	}
	deleteThreshold := s.cfg.DeleteThreshold
	if deleteThreshold <= 0 {
		deleteThreshold = 0.95
	}
	if topScore >= junkThreshold {
		dec.Action = "junk"
	}
	if s.cfg.DeleteEnabled && topScore >= deleteThreshold {
		dec.Action = "delete"
	}

	return dec, nil
}

// isAllowlisted skips builtin brand entries unless the message passed DMARC, since phishing forges those brands.
func (s *Snapshot) isAllowlisted(senderEmail, senderDomain string, dmarcPass bool) bool {
	email := strings.ToLower(strings.TrimSpace(senderEmail))
	domain := strings.ToLower(strings.TrimSpace(senderDomain))
	for _, entry := range s.allowlist {
		pat := strings.ToLower(strings.TrimSpace(entry.Pattern))
		if pat == "" || (entry.Builtin && !dmarcPass) {
			continue
		}
		if entry.Kind == "email" && email == pat {
			return true
		}
		if entry.Kind == "domain" && (domain == pat || strings.HasSuffix(domain, "."+pat)) {
			return true
		}
	}
	return false
}

// isOwnAddress catches copies of mail the user sent, which land in Sent or Archive.
func (s *Snapshot) isOwnAddress(senderEmail string) bool {
	own := strings.ToLower(strings.TrimSpace(s.cfg.IMAPUsername))
	return own != "" && strings.EqualFold(strings.TrimSpace(senderEmail), own)
}

func ParseSenderAddress(fromHeader string) (email, domain string) {
	trimmed := strings.TrimSpace(fromHeader)
	if trimmed == "" {
		return "", ""
	}
	addr, err := mail.ParseAddress(trimmed)
	raw := trimmed
	if err == nil && addr.Address != "" {
		raw = addr.Address
	}
	raw = strings.ToLower(strings.Trim(raw, "<> "))
	parts := strings.Split(raw, "@")
	if len(parts) != 2 {
		return raw, ""
	}
	return raw, strings.TrimSpace(parts[1])
}

func ExtractLinkDomains(text string) []string {
	matches := urlRegex.FindAllString(text, 64)
	seen := make(map[string]struct{})
	var out []string
	for _, m := range matches {
		u, err := url.Parse(strings.TrimRight(m, ".,;!?)]}"))
		if err != nil {
			continue
		}
		host := strings.ToLower(u.Hostname())
		if host == "" {
			continue
		}
		if _, ok := seen[host]; ok {
			continue
		}
		seen[host] = struct{}{}
		out = append(out, host)
		if len(out) >= 20 {
			break
		}
	}
	return out
}
