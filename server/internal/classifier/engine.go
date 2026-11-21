package classifier

import (
	"context"
	"fmt"
	"net/mail"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/mikaelweiss/eclean/server/internal/db"
	"github.com/mikaelweiss/eclean/server/internal/jev"
)

const maxBodySnippetLen = 2500

var urlRegex = regexp.MustCompile(`https?://[^\s"'<>()]+`)

type EmailInput struct {
	UIDValidity  uint32
	UID          uint32
	MessageID    string
	From         string
	ReplyTo      string
	SenderEmail  string
	SenderDomain string
	Subject      string
	AuthResults  string
	LinkDomains  []string
	BodySnippet  string
	EmailDate    time.Time
	RawHeaders   string
}

type Decision struct {
	Action       string
	CategoryID   string
	CategoryName string
	Confidence   float64
	Allowlisted  bool
	Scores       map[string]float64
}

type Engine struct {
	store     *db.Store
	evaluator jev.Evaluator
}

func NewEngine(store *db.Store, evaluator jev.Evaluator) *Engine {
	return &Engine{store: store, evaluator: evaluator}
}

func (e *Engine) Evaluate(ctx context.Context, in EmailInput) (Decision, error) {
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

	allowlisted, err := e.store.IsAllowlisted(senderEmail, senderDomain)
	if err != nil {
		return Decision{}, fmt.Errorf("check allowlist: %w", err)
	}
	if allowlisted {
		return Decision{Action: "keep", Allowlisted: true}, nil
	}

	cfg, err := e.store.GetSettings()
	if err != nil {
		return Decision{}, fmt.Errorf("load settings: %w", err)
	}
	cats, err := e.store.ListCategories()
	if err != nil {
		return Decision{}, fmt.Errorf("load categories: %w", err)
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
	if len(questions) == 0 {
		return Decision{Action: "keep"}, nil
	}

	eval := e.evaluator
	if eval == nil {
		if cfg.AIAPIKey == "" {
			return Decision{Action: "keep"}, nil
		}
		eval = jev.NewClient(cfg.AIProvider, cfg.AIAPIKey, cfg.AIModel)
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

	scores, err := eval.EvaluateNoul(ctx, state, questions)
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
	if c, ok := catByID[topID]; ok {
		dec.CategoryName = c.Name
	}

	if cfg.SpamAction == "delete" {
		threshold := cfg.DeleteThreshold
		if threshold <= 0 {
			threshold = 0.95
		}
		if topScore >= threshold {
			dec.Action = "delete"
		}
	} else {
		threshold := cfg.TrashThreshold
		if threshold <= 0 {
			threshold = 0.85
		}
		if topScore >= threshold {
			dec.Action = "trash"
		}
	}

	return dec, nil
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
