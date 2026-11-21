package abuse

import (
	"context"
	"fmt"
	"maps"
	"net"
	"regexp"
	"slices"
	"strings"

	"github.com/mikaelweiss/sift/server/internal/db"
)

const (
	KindNetwork        = "network"
	KindRegistrar      = "registrar"
	KindEmailService   = "email_service"
	KindLinkHost       = "link_host"
	KindLinkRegistrar  = "link_registrar"
	KindClearinghouse  = "phishing_clearinghouse"
	KindApple          = "apple"
	KindNetcraft       = "netcraft"
	netcraftAddress    = "report.netcraft.com"
	apwgAddress        = "reportphishing@apwg.org"
	applePhishAddress  = "reportphishing@apple.com"
	icloudAbuseAddress = "abuse@icloud.com"
	maxLinkDomains     = 3
)

// emailServiceAbuse maps an email service's signing or bounce domain to the address its own docs give for spam reports.
var emailServiceAbuse = map[string]string{
	"amazonses.com": "email-abuse@amazon.com",
	"sendgrid.net":  "abuse@sendgrid.com",
	"mailgun.org":   "abuse@mailgun.com",
	"mailgun.net":   "abuse@mailgun.com",
	"mailgun.com":   "abuse@mailgun.com",
}

// linkSkipDomains appear in legitimate and spam mail alike, so reporting their hosts would only add noise.
var linkSkipDomains = map[string]struct{}{
	"facebook.com": {}, "googleapis.com": {}, "gstatic.com": {}, "icloud.com": {}, "instagram.com": {},
	"twitter.com": {}, "w3.org": {}, "x.com": {}, "youtube.com": {},
}

var (
	dkimDomainRegex = regexp.MustCompile(`(?i)(?:^|;)\s*d=([a-z0-9.-]+)`)
	receivedFrom    = regexp.MustCompile(`(?i)^received:\s*from\s+([a-z0-9.-]+)`)
	angleAddr       = regexp.MustCompile(`<[^@>]*@([^>]+)>`)
	icloudDomains   = map[string]struct{}{"icloud.com": {}, "me.com": {}, "mac.com": {}}
)

// ResolveTargets lists every party that can act on this spam. Lookups that fail are skipped so one dead RDAP server
// does not block the rest.
func (r *Resolver) ResolveTargets(ctx context.Context, c Candidate, headers, sendingIP, rootDomain string) []db.AbuseTarget {
	var targets []db.AbuseTarget
	seen := map[string]struct{}{}
	add := func(kind, reason string, addresses ...string) {
		for _, a := range addresses {
			clean := strings.ToLower(strings.TrimSpace(a))
			if clean == "" {
				continue
			}
			if kind != KindNetcraft && !isValidEmail(clean) {
				continue
			}
			if _, dup := seen[clean]; dup {
				continue
			}
			seen[clean] = struct{}{}
			targets = append(targets, db.AbuseTarget{Address: clean, Kind: kind, Reason: reason})
		}
	}

	if sendingIP != "" {
		add(KindNetwork, fmt.Sprintf("Network that sent it (%s)", sendingIP), r.contacts(ctx, "ip", sendingIP)...)
	}
	if rootDomain != "" && !IsSharedMailProvider(rootDomain) {
		add(KindRegistrar, fmt.Sprintf("Registrar for %s", rootDomain), r.contacts(ctx, "domain", rootDomain)...)
	}
	services := emailServicesUsed(headers)
	for _, service := range slices.Sorted(maps.Keys(services)) {
		add(KindEmailService, fmt.Sprintf("Email service used to send it (%s)", service), services[service])
	}
	for _, domain := range reportableLinkDomains(c.LinkDomains, rootDomain) {
		if ip := r.firstPublicIP(ctx, domain); ip != "" {
			add(KindLinkHost, fmt.Sprintf("Hosts %s, linked in the email", domain), r.contacts(ctx, "ip", ip)...)
		}
		add(KindLinkRegistrar, fmt.Sprintf("Registrar for %s, linked in the email", domain), r.contacts(ctx, "domain", domain)...)
	}

	phishing := c.CategoryID == "phishing_scams"
	if phishing {
		add(KindClearinghouse, "Anti-Phishing Working Group, which feeds browser blocklists", apwgAddress)
	}
	if phishing && impersonatesApple(c, rootDomain) {
		add(KindApple, "Phishing that impersonates Apple", applePhishAddress)
	}
	if _, fromICloud := icloudDomains[rootDomain]; fromICloud {
		add(KindApple, "Sent from an iCloud account", icloudAbuseAddress)
	}
	if phishing || c.CategoryID == "crypto_gambling" {
		add(KindNetcraft, "Netcraft, which takes down phishing and scam sites", netcraftAddress)
	}
	return targets
}

func (r *Resolver) contacts(ctx context.Context, kind, value string) []string {
	list, err := r.lookupCached(ctx, kind+":"+value, func() ([]string, error) {
		return r.lookupTarget(ctx, kind, value)
	})
	if err != nil {
		return nil
	}
	return list
}

func (r *Resolver) firstPublicIP(ctx context.Context, host string) string {
	addrs, err := r.lookupIP(ctx, host)
	if err != nil {
		return ""
	}
	for _, a := range addrs {
		if ip := a.IP.To4(); ip != nil && !ip.IsPrivate() && !ip.IsLoopback() && !ip.IsUnspecified() {
			return ip.String()
		}
	}
	return ""
}

func emailServicesUsed(headers string) map[string]string {
	found := map[string]string{}
	check := func(host string) {
		root := RootDomain(host)
		if address, ok := emailServiceAbuse[root]; ok {
			found[root] = address
		}
	}
	for _, line := range unfoldHeaders(headers) {
		lower := strings.ToLower(line)
		switch {
		case strings.HasPrefix(lower, "dkim-signature:"):
			for _, m := range dkimDomainRegex.FindAllStringSubmatch(line[len("dkim-signature:"):], -1) {
				check(m[1])
			}
		case strings.HasPrefix(lower, "return-path:"):
			if m := angleAddr.FindStringSubmatch(line); m != nil {
				check(m[1])
			}
		case strings.HasPrefix(lower, "received:"):
			if m := receivedFrom.FindStringSubmatch(line); m != nil {
				check(m[1])
			}
		}
	}
	return found
}

func reportableLinkDomains(linkDomains []string, senderRoot string) []string {
	builtin := map[string]struct{}{}
	for _, d := range db.BuiltinAllowlistDomains {
		builtin[d] = struct{}{}
	}
	var out []string
	seen := map[string]struct{}{}
	for _, host := range linkDomains {
		root := RootDomain(host)
		if root == "" || root == senderRoot || IsSharedMailProvider(root) {
			continue
		}
		if _, skip := linkSkipDomains[root]; skip {
			continue
		}
		if _, skip := builtin[root]; skip {
			continue
		}
		if _, dup := seen[root]; dup {
			continue
		}
		seen[root] = struct{}{}
		out = append(out, root)
		if len(out) == maxLinkDomains {
			break
		}
	}
	return out
}

func impersonatesApple(c Candidate, rootDomain string) bool {
	if rootDomain == "apple.com" {
		return false
	}
	if _, ok := icloudDomains[rootDomain]; ok {
		return false
	}
	text := strings.ToLower(c.From + " " + c.Subject)
	return strings.Contains(text, "apple") || strings.Contains(text, "icloud")
}

func defaultLookupIP(ctx context.Context, host string) ([]net.IPAddr, error) {
	return net.DefaultResolver.LookupIPAddr(ctx, host)
}
