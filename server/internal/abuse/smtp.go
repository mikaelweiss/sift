package abuse

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"mime"
	"net"
	"net/smtp"
	"strings"
	"sync"
	"time"

	"github.com/mikaelweiss/sift/server/internal/db"
)

const (
	icloudSMTPHost = "smtp.mail.me.com"
	icloudSMTPPort = 587
)

type Mail struct {
	MessageID             string
	To                    string
	Subject               string
	Body                  string
	Attachment            []byte
	AttachmentName        string
	AttachmentContentType string
}

// NewReportMessageID generates an RFC 5322 Message-ID tagged for Sift abuse reply correlation.
func NewReportMessageID(from string) string {
	buf := make([]byte, 12)
	_, _ = rand.Read(buf)
	domain := "sift.local"
	if _, d, ok := strings.Cut(strings.TrimSpace(from), "@"); ok && d != "" {
		domain = strings.ToLower(d)
	}
	return fmt.Sprintf("<sift-abuse-%s@%s>", hex.EncodeToString(buf), domain)
}

type Sender interface {
	Send(ctx context.Context, cfg db.AppSettings, m Mail) error
}

// SMTPSender sends through iCloud with the same app-specific password Sift uses for IMAP.
type SMTPSender struct {
	mu          sync.Mutex
	lastSent    time.Time
	MinInterval time.Duration
}

func NewSMTPSender() *SMTPSender {
	return &SMTPSender{MinInterval: 5 * time.Second}
}

func (s *SMTPSender) Send(ctx context.Context, cfg db.AppSettings, m Mail) error {
	from := strings.TrimSpace(cfg.IMAPUsername)
	if from == "" || cfg.IMAPPassword == "" {
		return errors.New("iCloud email and app-specific password are required")
	}
	if err := s.throttle(ctx); err != nil {
		return err
	}

	addr := net.JoinHostPort(icloudSMTPHost, fmt.Sprint(icloudSMTPPort))
	conn, err := (&net.Dialer{Timeout: 15 * time.Second}).DialContext(ctx, "tcp", addr)
	if err != nil {
		return fmt.Errorf("smtp dial: %w", err)
	}
	client, err := smtp.NewClient(conn, icloudSMTPHost)
	if err != nil {
		_ = conn.Close()
		return fmt.Errorf("smtp client: %w", err)
	}
	defer client.Close()
	if err := client.StartTLS(&tls.Config{ServerName: icloudSMTPHost, MinVersion: tls.VersionTLS12}); err != nil {
		return fmt.Errorf("smtp starttls: %w", err)
	}
	if err := client.Auth(smtp.PlainAuth("", from, cfg.IMAPPassword, icloudSMTPHost)); err != nil {
		return fmt.Errorf("smtp auth: %w", err)
	}
	if err := client.Mail(from); err != nil {
		return fmt.Errorf("smtp mail from: %w", err)
	}
	if err := client.Rcpt(m.To); err != nil {
		return fmt.Errorf("smtp rcpt %s: %w", m.To, err)
	}
	w, err := client.Data()
	if err != nil {
		return fmt.Errorf("smtp data: %w", err)
	}
	if _, err := w.Write(BuildMessage(from, m)); err != nil {
		_ = w.Close()
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	return client.Quit()
}

// throttle spaces sends out so a burst of approvals does not trip iCloud's sending limits.
func (s *SMTPSender) throttle(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if wait := s.MinInterval - time.Since(s.lastSent); s.MinInterval > 0 && !s.lastSent.IsZero() && wait > 0 {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(wait):
		}
	}
	s.lastSent = time.Now()
	return nil
}

// BuildMessage writes a plain text report, with the evidence attached as message/rfc822 (or text/plain) when present.
func BuildMessage(from string, m Mail) []byte {
	var b strings.Builder
	if m.MessageID != "" {
		b.WriteString("Message-ID: " + m.MessageID + "\r\n")
	}
	b.WriteString("From: " + from + "\r\n")
	b.WriteString("To: " + m.To + "\r\n")
	b.WriteString("Subject: " + mime.QEncoding.Encode("utf-8", m.Subject) + "\r\n")
	b.WriteString("Date: " + time.Now().UTC().Format(time.RFC1123Z) + "\r\n")
	b.WriteString("MIME-Version: 1.0\r\n")
	body := toCRLF(m.Body)
	if len(m.Attachment) == 0 {
		b.WriteString("Content-Type: text/plain; charset=UTF-8\r\n\r\n")
		b.WriteString(body)
		return []byte(b.String())
	}

	boundary := randomBoundary()
	b.WriteString("Content-Type: multipart/mixed; boundary=\"" + boundary + "\"\r\n\r\n")
	b.WriteString("--" + boundary + "\r\n")
	b.WriteString("Content-Type: text/plain; charset=UTF-8\r\n\r\n")
	b.WriteString(body + "\r\n")
	b.WriteString("--" + boundary + "\r\n")
	if strings.EqualFold(m.AttachmentContentType, "text/plain") {
		b.WriteString("Content-Type: text/plain; charset=UTF-8; name=\"" + m.AttachmentName + "\"\r\n")
		b.WriteString("Content-Disposition: attachment; filename=\"" + m.AttachmentName + "\"\r\n")
		b.WriteString("Content-Transfer-Encoding: base64\r\n\r\n")
		b.WriteString(wrapBase64(m.Attachment))
	} else {
		b.WriteString("Content-Type: message/rfc822; name=\"" + m.AttachmentName + "\"\r\n")
		b.WriteString("Content-Disposition: attachment; filename=\"" + m.AttachmentName + "\"\r\n")
		// RFC 2046 allows only 7bit, 8bit or binary for message/rfc822, so the original goes in unencoded.
		b.WriteString("Content-Transfer-Encoding: 8bit\r\n\r\n")
		b.WriteString(strings.TrimRight(toCRLF(string(m.Attachment)), "\r\n") + "\r\n")
	}
	b.WriteString("--" + boundary + "--\r\n")
	return []byte(b.String())
}

func wrapBase64(data []byte) string {
	encoded := base64.StdEncoding.EncodeToString(data)
	var b strings.Builder
	for i := 0; i < len(encoded); i += 76 {
		end := min(i+76, len(encoded))
		b.WriteString(encoded[i:end])
		b.WriteString("\r\n")
	}
	return b.String()
}

func toCRLF(s string) string {
	return strings.ReplaceAll(strings.ReplaceAll(s, "\r\n", "\n"), "\n", "\r\n")
}

func randomBoundary() string {
	buf := make([]byte, 12)
	_, _ = rand.Read(buf)
	return "sift-" + hex.EncodeToString(buf)
}
