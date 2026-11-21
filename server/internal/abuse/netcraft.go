package abuse

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

const netcraftEndpoint = "https://report.netcraft.com/api/v3/report/email"

// netcraftSuccess is the message Netcraft returns for an accepted report.
const netcraftSuccess = "Successfully reported"

type netcraftReporter struct {
	client   *http.Client
	endpoint string
}

func newNetcraftReporter() *netcraftReporter {
	return &netcraftReporter{client: &http.Client{Timeout: 30 * time.Second}, endpoint: netcraftEndpoint}
}

// Report submits the raw message. Netcraft emails classification updates to reporterEmail.
func (n *netcraftReporter) Report(ctx context.Context, reporterEmail, message string) error {
	if strings.TrimSpace(message) == "" {
		return errors.New("no saved message to submit")
	}
	payload, _ := json.Marshal(map[string]string{"email": reporterEmail, "message": message})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, n.endpoint, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := n.client.Do(req)
	if err != nil {
		return fmt.Errorf("netcraft: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	var parsed struct {
		Message string `json:"message"`
	}
	_ = json.Unmarshal(body, &parsed)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("netcraft HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	if parsed.Message != netcraftSuccess {
		return fmt.Errorf("netcraft did not accept the report: %s", strings.TrimSpace(string(body)))
	}
	return nil
}
