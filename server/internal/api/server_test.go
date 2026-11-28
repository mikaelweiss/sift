package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/mikaelweiss/sift/server/internal/abuse"
	"github.com/mikaelweiss/sift/server/internal/db"
)

func TestPairingAuthAndCRUD(t *testing.T) {
	dir := t.TempDir()
	store, err := db.Open(dir)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer store.Close()

	_, fp, err := LoadOrGenerateTLS(dir)
	if err != nil || len(fp) != 64 {
		t.Fatalf("LoadOrGenerateTLS failed: fp=%q err=%v", fp, err)
	}

	abuseSvc := abuse.NewService(store, nil, nil)
	srv := NewServer(store, nil, nil, abuseSvc, NewHub(), "0.1.0", fp)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	// Public health works without auth.
	resp, err := http.Get(ts.URL + "/api/health")
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("health failed: status=%v err=%v", resp, err)
	}

	// Protected route rejects missing token.
	resp, err = http.Get(ts.URL + "/api/settings")
	if err != nil || resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 on settings without token")
	}

	// CLI pairing code redemption issues token for Mac #1.
	if err := store.CreatePairingCode(hashString("654321"), time.Minute); err != nil {
		t.Fatalf("create code: %v", err)
	}
	redeemResp, err := http.Post(ts.URL+"/api/pair/redeem", "application/json", bytes.NewBufferString(`{"code":"654321","device_name":"MacBook Pro"}`))
	if err != nil || redeemResp.StatusCode != http.StatusOK {
		t.Fatalf("redeem failed: %v", err)
	}
	var redeemBody struct {
		DeviceID string `json:"device_id"`
		Token    string `json:"token"`
	}
	_ = json.NewDecoder(redeemResp.Body).Decode(&redeemBody)
	if redeemBody.Token == "" {
		t.Fatalf("expected device token")
	}

	// Mac #2 requests live pairing; Mac #1 approves it.
	pairReqResp, _ := http.Post(ts.URL+"/api/pair/request", "application/json", bytes.NewBufferString(`{"device_name":"Mac Studio"}`))
	var pr struct {
		RequestID string `json:"request_id"`
	}
	_ = json.NewDecoder(pairReqResp.Body).Decode(&pr)

	approveReq, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/pair/approve", bytes.NewBufferString(`{"request_id":"`+pr.RequestID+`","approve":true}`))
	approveReq.Header.Set("Authorization", "Bearer "+redeemBody.Token)
	approveResp, err := http.DefaultClient.Do(approveReq)
	if err != nil || approveResp.StatusCode != http.StatusOK {
		t.Fatalf("approve failed: %v", err)
	}

	statusResp, _ := http.Get(ts.URL + "/api/pair/status/" + pr.RequestID)
	var st struct {
		Status string `json:"status"`
		Token  string `json:"token"`
	}
	_ = json.NewDecoder(statusResp.Body).Decode(&st)
	if st.Status != "approved" || st.Token == "" {
		t.Fatalf("expected approved status + one-time token, got %+v", st)
	}

	// Mac #2 can now create a custom category.
	catReq, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/categories", bytes.NewBufferString(`{"name":"Recruiters","description":"Unsolicited recruiting","enabled":true}`))
	catReq.Header.Set("Authorization", "Bearer "+st.Token)
	catResp, err := http.DefaultClient.Do(catReq)
	if err != nil || catResp.StatusCode != http.StatusCreated {
		t.Fatalf("create category failed: %v", err)
	}

	// Verify secrets are masked in GET /api/settings.
	putReq, _ := http.NewRequest(http.MethodPut, ts.URL+"/api/settings", bytes.NewBufferString(`{"imap_username":"me@icloud.com","imap_password":"secret-app-password"}`))
	putReq.Header.Set("Authorization", "Bearer "+st.Token)
	putResp, _ := http.DefaultClient.Do(putReq)
	var saved map[string]any
	_ = json.NewDecoder(putResp.Body).Decode(&saved)
	if saved["has_imap_password"] != true {
		t.Fatalf("expected has_imap_password=true, got %+v", saved)
	}
	if _, leaked := saved["imap_password"]; leaked {
		t.Fatalf("imap_password must not be returned by API")
	}

	// Verify health reports banned_count, history returns bans + learned form-only domains, and delete works.
	_, _ = store.RecordAbuseReply(db.AbuseReply{
		MessageID:       "ban-1@shockhosting.com",
		ReportedDomain:  "mostbau.com",
		Responder:       "abuse@shockhosting.com",
		ResponderDomain: "shockhosting.com",
		Subject:         "[Abuse Report] Unsolicited bulk email from mostbau.com",
		Snippet:         "The reported server has been suspended.",
		Outcome:         "action_taken",
	})
	_ = store.AddFormOnlyAbuseDomain("example-form.test", "learned")

	healthResp, err := http.Get(ts.URL + "/api/health")
	if err != nil || healthResp.StatusCode != http.StatusOK {
		t.Fatalf("health failed: %v", err)
	}
	var healthBody map[string]any
	_ = json.NewDecoder(healthResp.Body).Decode(&healthBody)
	if healthBody["banned_count"] != float64(1) {
		t.Fatalf("expected banned_count=1, got %+v", healthBody["banned_count"])
	}

	histReq, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/abuse/history", nil)
	histReq.Header.Set("Authorization", "Bearer "+st.Token)
	histResp, err := http.DefaultClient.Do(histReq)
	if err != nil || histResp.StatusCode != http.StatusOK {
		t.Fatalf("history failed: %v", err)
	}
	var histBody struct {
		BannedCount     int             `json:"banned_count"`
		Bans            []db.AbuseReply `json:"bans"`
		FormOnlyDomains []string        `json:"form_only_domains"`
	}
	_ = json.NewDecoder(histResp.Body).Decode(&histBody)
	if histBody.BannedCount != 1 || len(histBody.Bans) != 1 || len(histBody.FormOnlyDomains) != 1 {
		t.Fatalf("unexpected history response: %+v", histBody)
	}

	delReq, _ := http.NewRequest(http.MethodDelete, ts.URL+"/api/abuse/form-only/example-form.test", nil)
	delReq.Header.Set("Authorization", "Bearer "+st.Token)
	delResp, err := http.DefaultClient.Do(delReq)
	if err != nil || delResp.StatusCode != http.StatusNoContent {
		t.Fatalf("delete form-only failed: %v", err)
	}
	if remaining, _ := store.ListFormOnlyAbuseDomains(); len(remaining) != 0 {
		t.Fatalf("expected form-only domain deleted, got %v", remaining)
	}
}
