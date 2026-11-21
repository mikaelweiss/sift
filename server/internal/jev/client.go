package jev

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"strings"
	"time"
)

const (
	TypeSafeBaseURL   = "https://api.typesafe.ai/v1/systemone"
	OpenRouterBaseURL = "https://openrouter.ai/api/v1/systemone"
)

// MaxConcurrentRequests sizes the connection pool. Callers should not run more Jev calls in parallel than this.
const MaxConcurrentRequests = 48

// TypeSafe recommends HTTP/1.1 for high request rates because a single HTTP/2 connection caps throughput.
// A non-nil empty TLSNextProto stops Go from negotiating HTTP/2.
var defaultHTTPClient = &http.Client{
	Timeout: 30 * time.Second,
	Transport: &http.Transport{
		Proxy:               http.ProxyFromEnvironment,
		MaxIdleConns:        MaxConcurrentRequests,
		MaxIdleConnsPerHost: MaxConcurrentRequests,
		MaxConnsPerHost:     MaxConcurrentRequests,
		IdleConnTimeout:     90 * time.Second,
		TLSHandshakeTimeout: 10 * time.Second,
		ForceAttemptHTTP2:   false,
		TLSNextProto:        map[string]func(string, *tls.Conn) http.RoundTripper{},
	},
}

type Evaluator interface {
	EvaluateNoul(ctx context.Context, state any, questions map[string]NoulQuestion) (map[string]float64, error)
	VerifyKey(ctx context.Context) error
}

type Criteria struct {
	True  string `json:"true,omitempty"`
	False string `json:"false,omitempty"`
}

type NoulQuestion struct {
	Type         string    `json:"type"`
	Instructions string    `json:"instructions"`
	Criteria     *Criteria `json:"criteria,omitempty"`
}

type systemOneRequest struct {
	Model     string                  `json:"model"`
	State     any                     `json:"state"`
	Questions map[string]NoulQuestion `json:"questions"`
}

type systemOneResponse struct {
	Model   string                   `json:"model"`
	Answers map[string]answerPayload `json:"answers"`
	Error   *apiError                `json:"error,omitempty"`
}

type answerPayload struct {
	Type string   `json:"type"`
	Noul *float64 `json:"noul"`
}

type apiError struct {
	Message string `json:"message"`
}

type Client struct {
	Provider   string
	APIKey     string
	Model      string
	BaseURL    string
	HTTPClient *http.Client
	MaxRetries int
	RetryDelay time.Duration
}

func NewClient(provider, apiKey, model string) *Client {
	p := strings.ToLower(strings.TrimSpace(provider))
	if p == "" {
		p = "typesafe"
	}
	baseURL := TypeSafeBaseURL
	defaultModel := "jev-latest"
	if p == "openrouter" {
		baseURL = OpenRouterBaseURL
		defaultModel = "typesafe/jev-latest"
	}
	m := strings.TrimSpace(model)
	if m == "" {
		m = defaultModel
	} else if p == "openrouter" && !strings.Contains(m, "/") {
		m = "typesafe/" + m
	}

	return &Client{
		Provider:   p,
		APIKey:     strings.TrimSpace(apiKey),
		Model:      m,
		BaseURL:    baseURL,
		HTTPClient: defaultHTTPClient,
		MaxRetries: 7,
		RetryDelay: 500 * time.Millisecond,
	}
}

func (c *Client) EvaluateNoul(ctx context.Context, state any, questions map[string]NoulQuestion) (map[string]float64, error) {
	if c.APIKey == "" {
		return nil, errors.New("API key is empty")
	}
	if len(questions) == 0 {
		return map[string]float64{}, nil
	}

	normalized := make(map[string]NoulQuestion, len(questions))
	for k, q := range questions {
		q.Type = "noul"
		normalized[k] = q
	}

	bodyBytes, err := json.Marshal(systemOneRequest{
		Model:     c.Model,
		State:     state,
		Questions: normalized,
	})
	if err != nil {
		return nil, fmt.Errorf("marshal request: %w", err)
	}

	httpClient := c.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 30 * time.Second}
	}
	attempts := c.MaxRetries
	if attempts < 1 {
		attempts = 1
	}
	delay := c.RetryDelay
	if delay <= 0 {
		delay = 500 * time.Millisecond
	}

	var lastErr error
	for attempt := 0; attempt < attempts; attempt++ {
		if attempt > 0 {
			// Jitter keeps parallel workers that hit a 429 together from retrying in lockstep.
			backoff := delay * time.Duration(1<<(attempt-1))
			wait := backoff/2 + time.Duration(rand.Int64N(int64(backoff)))
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(wait):
			}
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL, bytes.NewReader(bodyBytes))
		if err != nil {
			return nil, fmt.Errorf("create request: %w", err)
		}
		req.Header.Set("Authorization", "Bearer "+c.APIKey)
		req.Header.Set("Content-Type", "application/json")
		if c.Provider == "openrouter" {
			req.Header.Set("X-Title", "Sift")
		}

		resp, err := httpClient.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		respBytes, readErr := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
		_ = resp.Body.Close()
		if readErr != nil {
			lastErr = readErr
			continue
		}

		if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500 {
			lastErr = fmt.Errorf("systemone HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(respBytes)))
			continue
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return nil, fmt.Errorf("systemone HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(respBytes)))
		}

		var parsed systemOneResponse
		if err := json.Unmarshal(respBytes, &parsed); err != nil {
			return nil, fmt.Errorf("decode systemone response: %w", err)
		}
		if parsed.Error != nil && parsed.Error.Message != "" {
			return nil, errors.New(parsed.Error.Message)
		}

		scores := make(map[string]float64, len(parsed.Answers))
		for k, ans := range parsed.Answers {
			if ans.Noul != nil {
				scores[k] = *ans.Noul
			}
		}
		return scores, nil
	}
	return nil, lastErr
}

func (c *Client) VerifyKey(ctx context.Context) error {
	_, err := c.EvaluateNoul(ctx, map[string]string{"text": "Hello"}, map[string]NoulQuestion{
		"ping": {
			Type:         "noul",
			Instructions: "Is this a greeting?",
		},
	})
	return err
}
