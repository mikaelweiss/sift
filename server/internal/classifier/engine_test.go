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

	// Default junk threshold is 0.85 -> 0.90 goes to Junk.
	dec, err = engine.Evaluate(context.Background(), EmailInput{
		From:    "Scammer <bad@evil.test>",
		Subject: "Verify your account",
	})
	if err != nil {
		t.Fatalf("junk eval: %v", err)
	}
	if dec.Action != "junk" || dec.CategoryID != "phishing_scams" {
		t.Fatalf("expected junk phishing_scams, got %+v", dec)
	}

	// Permanent delete on (0.95 threshold) -> 0.90 still goes to Junk.
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
	if dec.Action != "junk" {
		t.Fatalf("expected 0.90 junked below the delete threshold, got %+v", dec)
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

func TestClassifierKeepsMailFromOwnAddress(t *testing.T) {
	store, err := db.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	cfg, _ := store.GetSettings()
	cfg.IMAPUsername = "me@icloud.com"
	if err := store.SaveSettings(cfg); err != nil {
		t.Fatal(err)
	}
	stub := &stubEvaluator{scores: map[string]float64{"cold_sales": 0.99}}
	dec, err := NewEngine(store, stub).Evaluate(context.Background(), EmailInput{
		From:    "Me <Me@iCloud.com>",
		Subject: "Paid partnership",
	})
	if err != nil {
		t.Fatal(err)
	}
	if dec.Action != "keep" || stub.called != 0 {
		t.Fatalf("own sent mail was classified: %+v, Jev calls %d", dec, stub.called)
	}
}

func TestBuiltinAllowlistRequiresDMARC(t *testing.T) {
	store, err := db.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	stub := &stubEvaluator{scores: map[string]float64{"phishing_scams": 0.97}}
	engine := NewEngine(store, stub)

	genuine, err := engine.Evaluate(context.Background(), EmailInput{From: "Apple <no_reply@email.apple.com>", Subject: "Your repair request is pending.", DMARCPass: true})
	if err != nil {
		t.Fatal(err)
	}
	if !genuine.Allowlisted || genuine.Action != "keep" {
		t.Fatalf("DMARC-passing apple.com mail was not allowlisted: %+v", genuine)
	}

	forged, err := engine.Evaluate(context.Background(), EmailInput{From: "Apple <no_reply@email.apple.com>", Subject: "Verify your Apple ID"})
	if err != nil {
		t.Fatal(err)
	}
	if forged.Allowlisted || forged.Action != "junk" {
		t.Fatalf("apple.com mail without DMARC skipped classification: %+v", forged)
	}
}
