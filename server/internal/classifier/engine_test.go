package classifier

import (
	"context"
	"testing"

	"github.com/mikaelweiss/sift/server/internal/db"
	"github.com/mikaelweiss/sift/server/internal/jev"
)

type stubEvaluator struct {
	scores map[string]float64
	called int
}

func (s *stubEvaluator) EvaluateNoul(_ context.Context, _ any, _ map[string]jev.NoulQuestion) (map[string]float64, error) {
	s.called++
	return s.scores, nil
}

func (s *stubEvaluator) VerifyKey(_ context.Context) error { return nil }

func TestClassifierAllowlistAndThresholds(t *testing.T) {
	store, err := db.Open(t.TempDir())
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer store.Close()

	if _, err := store.AddAllowlistEntry("trustedbank.com", "domain"); err != nil {
		t.Fatalf("add allowlist: %v", err)
	}

	stub := &stubEvaluator{scores: map[string]float64{"phishing_scams": 0.90, "marketing_promotions": 0.40}}
	engine := NewEngine(store, stub)

	dec, err := engine.Evaluate(context.Background(), EmailInput{
		From:    "Alerts <alerts@mail.trustedbank.com>",
		Subject: "Statement ready",
	})
	if err != nil {
		t.Fatalf("allowlist eval: %v", err)
	}
	if !dec.Allowlisted || dec.Action != "keep" || stub.called != 0 {
		t.Fatalf("expected allowlist bypass without calling Jev, got %+v calls=%d", dec, stub.called)
	}

	// Default mode is trash with 0.85 threshold -> 0.90 should trash.
	dec, err = engine.Evaluate(context.Background(), EmailInput{
		From:    "Scammer <bad@evil.test>",
		Subject: "Verify your account",
	})
	if err != nil {
		t.Fatalf("trash eval: %v", err)
	}
	if dec.Action != "trash" || dec.CategoryID != "phishing_scams" {
		t.Fatalf("expected trash phishing_scams, got %+v", dec)
	}

	// Permanent delete on (0.95 threshold) -> 0.90 still trashes.
	cfg, _ := store.GetSettings()
	cfg.DeleteEnabled = true
	_ = store.SaveSettings(cfg)

	dec, err = engine.Evaluate(context.Background(), EmailInput{
		From:    "Scammer <bad@evil.test>",
		Subject: "Verify your account",
	})
	if err != nil {
		t.Fatalf("delete borderline eval: %v", err)
	}
	if dec.Action != "trash" {
		t.Fatalf("expected 0.90 trashed below the delete threshold, got %+v", dec)
	}

	stub.scores["phishing_scams"] = 0.97
	dec, err = engine.Evaluate(context.Background(), EmailInput{
		From:    "Scammer <bad@evil.test>",
		Subject: "Verify your account",
	})
	if err != nil {
		t.Fatalf("delete high confidence eval: %v", err)
	}
	if dec.Action != "delete" {
		t.Fatalf("expected delete at 0.97, got %+v", dec)
	}
}

func TestExtractLinkDomainsAndSender(t *testing.T) {
	email, domain := ParseSenderAddress(`"Promo Team" <Offer@Sub.Shop.Example>`)
	if email != "offer@sub.shop.example" || domain != "sub.shop.example" {
		t.Fatalf("unexpected sender parse: %s / %s", email, domain)
	}
	domains := ExtractLinkDomains("Visit https://evil.test/login and https://evil.test/a and http://track.spam.org/1.")
	if len(domains) != 2 || domains[0] != "evil.test" || domains[1] != "track.spam.org" {
		t.Fatalf("unexpected domains: %+v", domains)
	}
}
