package unsubscribe

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestOneClickPostsTheRFC8058Body(t *testing.T) {
	var gotBody, gotType, gotMethod string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		gotBody, gotType, gotMethod = string(b), r.Header.Get("Content-Type"), r.Method
	}))
	defer srv.Close()

	if err := newClient(srv.Client().Transport).OneClick(context.Background(), srv.URL+"/u?id=1"); err != nil {
		t.Fatal(err)
	}
	if gotMethod != http.MethodPost || gotBody != "List-Unsubscribe=One-Click" || gotType != "application/x-www-form-urlencoded" {
		t.Fatalf("got %s %q (%s)", gotMethod, gotBody, gotType)
	}
}

func TestOneClickRefusesPrivateAddressesAndPlainHTTP(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Error("request reached a loopback server")
	}))
	defer srv.Close()

	err := New().OneClick(context.Background(), srv.URL)
	if err == nil || !strings.Contains(err.Error(), "non-public") {
		t.Fatalf("loopback request was not refused: %v", err)
	}
	if err := New().OneClick(context.Background(), "http://example.com/u"); err == nil {
		t.Fatal("plain http link was accepted")
	}
}
