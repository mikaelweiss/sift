package jev

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestNewClientDefaults(t *testing.T) {
	ts := NewClient("typesafe", "key1", "")
	if ts.BaseURL != TypeSafeBaseURL || ts.Model != "jev-latest" {
		t.Fatalf("unexpected typesafe defaults: %+v", ts)
	}

	or := NewClient("openrouter", "key2", "jev-latest")
	if or.BaseURL != OpenRouterBaseURL || or.Model != "typesafe/jev-latest" {
		t.Fatalf("unexpected openrouter defaults: %+v", or)
	}
}

func TestEvaluateNoulRetryAndParse(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := calls.Add(1)
		if r.Header.Get("Authorization") != "Bearer secret-key" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if n == 1 {
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = w.Write([]byte("rate limited"))
			return
		}
		var req systemOneRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("decode req: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if req.Questions["spam"].Type != "noul" {
			t.Errorf("expected noul type")
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"model":"jev-latest","answers":{"spam":{"type":"noul","noul":0.97}}}`))
	}))
	defer srv.Close()

	client := NewClient("typesafe", "secret-key", "")
	client.BaseURL = srv.URL
	client.RetryDelay = 10 * time.Millisecond

	scores, err := client.EvaluateNoul(context.Background(), map[string]string{"subject": "Win cash"}, map[string]NoulQuestion{
		"spam": {Instructions: "Is this spam?"},
	})
	if err != nil {
		t.Fatalf("EvaluateNoul failed: %v", err)
	}
	if calls.Load() != 2 {
		t.Fatalf("expected 2 calls with retry, got %d", calls.Load())
	}
	if scores["spam"] != 0.97 {
		t.Fatalf("expected 0.97, got %f", scores["spam"])
	}
}

func TestVerifyKeyAuthFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":{"message":"invalid key"}}`))
	}))
	defer srv.Close()

	client := NewClient("openrouter", "bad-key", "")
	client.BaseURL = srv.URL
	if err := client.VerifyKey(context.Background()); err == nil {
		t.Fatalf("expected auth error")
	}
}
