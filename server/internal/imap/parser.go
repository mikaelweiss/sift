package imap

import (
	"bytes"
	"encoding/base64"
	"io"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"net/mail"
	"regexp"
	"strings"
	"time"

	"github.com/mikaelweiss/sift/server/internal/classifier"
)

var (
	htmlTagRegex    = regexp.MustCompile(`<[^>]+>`)
	whitespaceRegex = regexp.MustCompile(`\s+`)
	dmarcRegex      = regexp.MustCompile(`dmarc=([a-z]+)[^;]*?header\.from=([a-z0-9.-]+)`)
	angleURLRegex   = regexp.MustCompile(`<([^>]+)>`)
)

// trustedAuthServ lists the authserv-ids iCloud stamps on inbound mail.
var trustedAuthServ = []string{"icloud.com", "me.com"}

func ParseRawMessage(uidValidity, uid uint32, internalDate time.Time, raw []byte) classifier.EmailInput {
	headerBytes, _ := splitRawHeaderBody(raw)
	msg, err := mail.ReadMessage(bytes.NewReader(raw))
	if err != nil {
		return classifier.EmailInput{
			UIDValidity: uidValidity,
			UID:         uid,
			EmailDate:   fallbackTime(internalDate),
			RawHeaders:  string(headerBytes),
			BodySnippet: truncateText(string(raw), 2500),
		}
	}

	from := decodeHeader(msg.Header.Get("From"))
	unsubscribeURL := oneClickUnsubscribeURL(msg.Header.Get("List-Unsubscribe"), msg.Header.Get("List-Unsubscribe-Post"))
	replyTo := decodeHeader(msg.Header.Get("Reply-To"))
	subject := decodeHeader(msg.Header.Get("Subject"))
	messageID := strings.TrimSpace(msg.Header.Get("Message-ID"))
	authResults := strings.Join(msg.Header["Authentication-Results"], " ; ")
	senderEmail, senderDomain := classifier.ParseSenderAddress(from)

	emailDate := fallbackTime(internalDate)
	if parsedDate, dateErr := msg.Header.Date(); dateErr == nil && !parsedDate.IsZero() {
		emailDate = parsedDate.UTC()
	}

	bodyText, rawForLinks := extractBodyText(msg.Header.Get("Content-Type"), msg.Header.Get("Content-Transfer-Encoding"), msg.Body)
	linkDomains := classifier.ExtractLinkDomains(rawForLinks + "\n" + bodyText)

	return classifier.EmailInput{
		UIDValidity:    uidValidity,
		UID:            uid,
		RawMessage:     string(raw),
		DMARCPass:      dmarcPassFor(msg.Header["Authentication-Results"], senderDomain),
		UnsubscribeURL: unsubscribeURL,
		MessageID:      messageID,
		From:           from,
		ReplyTo:        replyTo,
		SenderEmail:    senderEmail,
		SenderDomain:   senderDomain,
		Subject:        subject,
		AuthResults:    authResults,
		LinkDomains:    linkDomains,
		BodySnippet:    truncateText(bodyText, 2500),
		EmailDate:      emailDate,
		RawHeaders:     string(headerBytes),
	}
}

// dmarcPassFor reads the first DMARC verdict stamped by iCloud. iCloud evaluates every inbound message
// and its headers sit above the sender's own, so a forged verdict inside the message always comes later.
func dmarcPassFor(authResults []string, senderDomain string) bool {
	domain := strings.ToLower(strings.TrimSpace(senderDomain))
	if domain == "" {
		return false
	}
	for _, h := range authResults {
		authserv, rest, ok := strings.Cut(strings.ToLower(h), ";")
		if !ok || !isTrustedAuthServ(strings.TrimSpace(authserv)) {
			continue
		}
		m := dmarcRegex.FindStringSubmatch(rest)
		if m == nil {
			continue
		}
		return m[1] == "pass" && m[2] == domain
	}
	return false
}

func isTrustedAuthServ(authserv string) bool {
	fields := strings.Fields(authserv)
	if len(fields) == 0 {
		return false
	}
	id := fields[0]
	for _, trusted := range trustedAuthServ {
		if id == trusted || strings.HasSuffix(id, "."+trusted) {
			return true
		}
	}
	return false
}

// oneClickUnsubscribeURL returns the RFC 8058 HTTPS endpoint, or "" when the sender does not offer one-click unsubscribe.
func oneClickUnsubscribeURL(listUnsubscribe, listUnsubscribePost string) string {
	if !strings.Contains(strings.ToLower(listUnsubscribePost), "list-unsubscribe=one-click") {
		return ""
	}
	for _, m := range angleURLRegex.FindAllStringSubmatch(listUnsubscribe, -1) {
		candidate := strings.TrimSpace(m[1])
		if strings.HasPrefix(strings.ToLower(candidate), "https://") {
			return candidate
		}
	}
	return ""
}

func splitRawHeaderBody(raw []byte) (headers, body []byte) {
	if idx := bytes.Index(raw, []byte("\r\n\r\n")); idx >= 0 {
		return raw[:idx], raw[idx+4:]
	}
	if idx := bytes.Index(raw, []byte("\n\n")); idx >= 0 {
		return raw[:idx], raw[idx+2:]
	}
	return raw, nil
}

func decodeHeader(val string) string {
	dec := new(mime.WordDecoder)
	out, err := dec.DecodeHeader(val)
	if err != nil {
		return strings.TrimSpace(val)
	}
	return strings.TrimSpace(out)
}

func extractBodyText(contentType, transferEncoding string, r io.Reader) (plain string, rawForLinks string) {
	mediaType, params, err := mime.ParseMediaType(contentType)
	if err != nil {
		mediaType = "text/plain"
	}

	if strings.HasPrefix(strings.ToLower(mediaType), "multipart/") && params["boundary"] != "" {
		mr := multipart.NewReader(r, params["boundary"])
		var textPart, htmlPart string
		for i := 0; i < 16; i++ {
			part, pErr := mr.NextPart()
			if pErr != nil {
				break
			}
			pt, pRaw := extractBodyText(part.Header.Get("Content-Type"), part.Header.Get("Content-Transfer-Encoding"), io.LimitReader(part, 256<<10))
			_ = part.Close()
			partMedia, _, _ := mime.ParseMediaType(part.Header.Get("Content-Type"))
			if strings.EqualFold(partMedia, "text/plain") && textPart == "" {
				textPart = pt
				rawForLinks += "\n" + pRaw
			} else if strings.EqualFold(partMedia, "text/html") && htmlPart == "" {
				htmlPart = pt
				rawForLinks += "\n" + pRaw
			} else if textPart == "" && pt != "" {
				textPart = pt
				rawForLinks += "\n" + pRaw
			}
		}
		if textPart != "" {
			return textPart, rawForLinks
		}
		return htmlPart, rawForLinks
	}

	decodedReader := decodeTransfer(r, transferEncoding)
	data, _ := io.ReadAll(io.LimitReader(decodedReader, 256<<10))
	rawStr := string(data)

	if strings.EqualFold(mediaType, "text/html") {
		stripped := htmlTagRegex.ReplaceAllString(rawStr, " ")
		stripped = whitespaceRegex.ReplaceAllString(stripped, " ")
		return strings.TrimSpace(stripped), rawStr
	}
	return strings.TrimSpace(rawStr), rawStr
}

func decodeTransfer(r io.Reader, encoding string) io.Reader {
	switch strings.ToLower(strings.TrimSpace(encoding)) {
	case "quoted-printable":
		return quotedprintable.NewReader(r)
	case "base64":
		return base64.NewDecoder(base64.StdEncoding, r)
	default:
		return r
	}
}

func truncateText(s string, maxLen int) string {
	s = strings.TrimSpace(s)
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen]
}

func fallbackTime(t time.Time) time.Time {
	if !t.IsZero() {
		return t.UTC()
	}
	return time.Now().UTC()
}
