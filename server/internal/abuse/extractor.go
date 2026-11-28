package abuse

import (
	"net/netip"
	"regexp"
	"strings"

	"golang.org/x/net/publicsuffix"
)

var sharedProviders = map[string]struct{}{
	"gmail.com":      {},
	"googlemail.com": {},
	"icloud.com":     {},
	"me.com":         {},
	"mac.com":        {},
	"outlook.com":    {},
	"hotmail.com":    {},
	"live.com":       {},
	"msn.com":        {},
	"yahoo.com":      {},
	"ymail.com":      {},
	"aol.com":        {},
	"att.net":        {},
	"sbcglobal.net":  {},
	"bellsouth.net":  {},
	"comcast.net":    {},
	"verizon.net":    {},
	"cox.net":        {},
	"gmx.com":        {},
	"gmx.net":        {},
	"proton.me":      {},
	"protonmail.com": {},
	"fastmail.com":   {},
}

var (
	ipTokenRegex      = regexp.MustCompile(`\[([0-9a-fA-F:.]+)\]|\b(\d{1,3}(?:\.\d{1,3}){3})\b`)
	forClauseRegex    = regexp.MustCompile(`(?i)(\bfor\s+)(<[^>]+>|[^\s;]+)`)
	recipientHdrRegex = regexp.MustCompile(`(?im)^(To|Delivered-To|X-Original-To|Envelope-To):\s*.*$`)
)

func RootDomain(host string) string {
	clean := strings.ToLower(strings.Trim(strings.TrimSpace(host), "."))
	if clean == "" {
		return ""
	}
	if strings.Contains(clean, "@") {
		parts := strings.Split(clean, "@")
		clean = parts[len(parts)-1]
	}
	etld, err := publicsuffix.EffectiveTLDPlusOne(clean)
	if err != nil {
		return clean
	}
	return etld
}

func IsSharedMailProvider(rootDomain string) bool {
	_, ok := sharedProviders[strings.ToLower(strings.TrimSpace(rootDomain))]
	return ok
}

func ExtractOriginatingIP(rawHeaders string) string {
	lines := unfoldHeaders(rawHeaders)
	var received []string
	for _, line := range lines {
		if strings.HasPrefix(strings.ToLower(line), "received:") {
			received = append(received, line)
		}
	}
	// Walk bottom-to-top to find the earliest external sending hop.
	for i := len(received) - 1; i >= 0; i-- {
		lower := strings.ToLower(received[i])
		if strings.Contains(lower, ".icloud.com") || strings.Contains(lower, ".me.com") || strings.Contains(lower, ".apple.com") {
			if ip := firstPublicIP(received[i]); ip != "" {
				return ip
			}
			continue
		}
		if ip := firstPublicIP(received[i]); ip != "" {
			return ip
		}
	}
	for _, line := range received {
		if ip := firstPublicIP(line); ip != "" {
			return ip
		}
	}
	return ""
}

func firstPublicIP(line string) string {
	matches := ipTokenRegex.FindAllStringSubmatch(line, -1)
	for _, m := range matches {
		candidate := m[1]
		if candidate == "" {
			candidate = m[2]
		}
		candidate = strings.TrimPrefix(strings.ToLower(candidate), "ipv6:")
		addr, err := netip.ParseAddr(candidate)
		if err != nil {
			continue
		}
		if isPublicAddr(addr) {
			return addr.String()
		}
	}
	return ""
}

func isPublicAddr(addr netip.Addr) bool {
	if !addr.IsValid() || addr.IsLoopback() || addr.IsPrivate() || addr.IsLinkLocalUnicast() || addr.IsLinkLocalMulticast() || addr.IsMulticast() || addr.IsUnspecified() {
		return false
	}
	return true
}

func unfoldHeaders(raw string) []string {
	normalized := strings.ReplaceAll(raw, "\r\n", "\n")
	rawLines := strings.Split(normalized, "\n")
	var out []string
	for _, line := range rawLines {
		if line == "" {
			break
		}
		if (strings.HasPrefix(line, " ") || strings.HasPrefix(line, "\t")) && len(out) > 0 {
			out[len(out)-1] += " " + strings.TrimSpace(line)
			continue
		}
		out = append(out, line)
	}
	return out
}

func RedactHeaders(rawHeaders string, redactEmails ...string) string {
	result := recipientHdrRegex.ReplaceAllString(rawHeaders, `$1: [REDACTED]`)
	result = forClauseRegex.ReplaceAllString(result, `${1}[REDACTED]`)
	for _, email := range redactEmails {
		clean := strings.TrimSpace(email)
		if clean == "" {
			continue
		}
		re := regexp.MustCompile(`(?i)` + regexp.QuoteMeta(clean))
		result = re.ReplaceAllString(result, "[REDACTED]")
	}
	return result
}
