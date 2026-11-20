package abuse

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/smtp"
	"strings"
	"sync"
	"time"

	"github.com/mikaelweiss/eclean/server/internal/db"
)

type Sender interface {
	Send(ctx context.Context, cfg db.AppSettings, to []string, subject, body string) error
}

type SMTPSender struct {
	mu          sync.Mutex
	lastSent    time.Time
	MinInterval time.Duration
}

func NewSMTPSender() *SMTPSender {
	return &SMTPSender{MinInterval: 10 * time.Second}
}

func (s *SMTPSender) Send(ctx context.Context, cfg db.AppSettings, to []string, subject, body string) error {
	if len(to) == 0 {
		return errors.New("no abuse recipients")
	}

	s.mu.Lock()
	if s.MinInterval > 0 && !s.lastSent.IsZero() {
		wait := s.MinInterval - time.Since(s.lastSent)
		if wait > 0 {
			s.mu.Unlock()
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(wait):
			}
			s.mu.Lock()
		}
	}
	s.lastSent = time.Now()
	s.mu.Unlock()

	host, port, username, password, fromAddr, err := resolveSMTPConfig(cfg)
	if err != nil {
		return err
	}

	msg := buildMessage(fromAddr, to, subject, body)
	addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))

	var client *smtp.Client
	if port == 465 {
		tlsConn, err := tls.DialWithDialer(&net.Dialer{Timeout: 15 * time.Second}, "tcp", addr, &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12})
		if err != nil {
			return fmt.Errorf("smtp tls dial: %w", err)
		}
		client, err = smtp.NewClient(tlsConn, host)
		if err != nil {
			_ = tlsConn.Close()
			return fmt.Errorf("smtp client: %w", err)
		}
	} else {
		conn, err := (&net.Dialer{Timeout: 15 * time.Second}).DialContext(ctx, "tcp", addr)
		if err != nil {
			return fmt.Errorf("smtp dial: %w", err)
		}
		client, err = smtp.NewClient(conn, host)
		if err != nil {
			_ = conn.Close()
			return fmt.Errorf("smtp client: %w", err)
		}
		if ok, _ := client.Extension("STARTTLS"); ok {
			if err := client.StartTLS(&tls.Config{ServerName: host, MinVersion: tls.VersionTLS12}); err != nil {
				_ = client.Close()
				return fmt.Errorf("smtp starttls: %w", err)
			}
		}
	}
	defer client.Close()

	if username != "" && password != "" {
		auth := smtp.PlainAuth("", username, password, host)
		if err := client.Auth(auth); err != nil {
			return fmt.Errorf("smtp auth: %w", err)
		}
	}
	if err := client.Mail(fromAddr); err != nil {
		return fmt.Errorf("smtp mail from: %w", err)
	}
	for _, rcpt := range to {
		if err := client.Rcpt(rcpt); err != nil {
			return fmt.Errorf("smtp rcpt %s: %w", rcpt, err)
		}
	}
	w, err := client.Data()
	if err != nil {
		return fmt.Errorf("smtp data: %w", err)
	}
	if _, err := w.Write([]byte(msg)); err != nil {
		_ = w.Close()
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	return client.Quit()
}

func resolveSMTPConfig(cfg db.AppSettings) (host string, port int, username, password, fromAddr string, err error) {
	if cfg.AbuseSMTPMode == "custom" {
		host = strings.TrimSpace(cfg.AbuseSMTPHost)
		port = cfg.AbuseSMTPPort
		if port == 0 {
			port = 587
		}
		username = strings.TrimSpace(cfg.AbuseSMTPUsername)
		password = cfg.AbuseSMTPPassword
		fromAddr = strings.TrimSpace(cfg.AbuseFromEmail)
		if host == "" || fromAddr == "" {
			return "", 0, "", "", "", errors.New("custom SMTP host and sender email are required")
		}
		return host, port, username, password, fromAddr, nil
	}

	host = "smtp.mail.me.com"
	port = 587
	username = strings.TrimSpace(cfg.IMAPUsername)
	password = cfg.IMAPPassword
	fromAddr = strings.TrimSpace(cfg.AbuseFromEmail)
	if fromAddr == "" {
		fromAddr = username
	}
	if username == "" || password == "" || fromAddr == "" {
		return "", 0, "", "", "", errors.New("iCloud credentials and sender address are required")
	}
	return host, port, username, password, fromAddr, nil
}

func buildMessage(from string, to []string, subject, body string) string {
	var b strings.Builder
	b.WriteString("From: " + from + "\r\n")
	b.WriteString("To: " + strings.Join(to, ", ") + "\r\n")
	b.WriteString("Subject: " + subject + "\r\n")
	b.WriteString("Date: " + time.Now().UTC().Format(time.RFC1123Z) + "\r\n")
	b.WriteString("MIME-Version: 1.0\r\n")
	b.WriteString("Content-Type: text/plain; charset=UTF-8\r\n")
	b.WriteString("\r\n")
	b.WriteString(body)
	return b.String()
}

func FormatReport(item db.AbuseQueueItem) (subject, body string) {
	prefix := "Abuse Report"
	if item.RepeatOffense {
		prefix = "Repeat Abuse Report"
	}
	subject = fmt.Sprintf("[%s] Unsolicited spam/phishing from %s (%s)", prefix, item.RootDomain, item.SendingIP)

	var b strings.Builder
	b.WriteString("Hello Abuse Desk,\n\n")
	b.WriteString("We are reporting unsolicited abusive email originating from infrastructure under your administration.\n\n")
	b.WriteString(fmt.Sprintf("Offending domain: %s\n", item.RootDomain))
	if item.SendingIP != "" {
		b.WriteString(fmt.Sprintf("Originating IP: %s\n", item.SendingIP))
	}
	b.WriteString(fmt.Sprintf("Category: %s (confidence %.2f)\n", item.CategoryID, item.Confidence))
	b.WriteString(fmt.Sprintf("Messages observed: %d\n", item.HitCount))
	if item.RepeatOffense && item.PreviousReportedAt != "" {
		b.WriteString(fmt.Sprintf("Repeat offense: previously reported on %s\n", item.PreviousReportedAt))
	}
	b.WriteString("\nRedacted original headers (recipient address removed for privacy):\n")
	b.WriteString("------------------------------------------------------------\n")
	b.WriteString(item.RedactedHeaders)
	b.WriteString("\n------------------------------------------------------------\n")
	return subject, b.String()
}
