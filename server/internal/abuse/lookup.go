package abuse

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/mail"
	"regexp"
	"strings"
	"time"

	"github.com/mikaelweiss/eclean/server/internal/db"
)

const (
	defaultRDAPBase = "https://rdap.org"
	cacheTTL        = 24 * time.Hour
)

var (
	whoisAbuseRegex = regexp.MustCompile(`(?i)(?:abuse[^\n:]*email|orgabuseemail|registrar abuse contact email)\s*:\s*([^\s,]+)`)
	genericAbuseRe  = regexp.MustCompile(`(?i)\babuse@[a-z0-9.-]+\.[a-z]{2,}\b`)
	whoisReferRegex = regexp.MustCompile(`(?i)^(?:refer|whois)\s*:\s*([^\s]+)`)
)

type Resolver struct {
	store      *db.Store
	httpClient *http.Client
	rdapBase   string
	whoisDial  func(ctx context.Context, server, query string) (string, error)
}

func NewResolver(store *db.Store) *Resolver {
	return &Resolver{
		store:      store,
		httpClient: &http.Client{Timeout: 8 * time.Second},
		rdapBase:   defaultRDAPBase,
		whoisDial:  queryWHOISServer,
	}
}

func (r *Resolver) ResolveContacts(ctx context.Context, sendingIP, rootDomain string) ([]string, error) {
	seen := make(map[string]struct{})
	var contacts []string
	add := func(list []string) {
		for _, c := range list {
			clean := strings.ToLower(strings.TrimSpace(c))
			if !isValidEmail(clean) {
				continue
			}
			if _, ok := seen[clean]; ok {
				continue
			}
			seen[clean] = struct{}{}
			contacts = append(contacts, clean)
		}
	}

	if sendingIP != "" {
		if ipContacts, err := r.lookupCached(ctx, "ip:"+sendingIP, func() ([]string, error) {
			return r.lookupTarget(ctx, "ip", sendingIP)
		}); err == nil {
			add(ipContacts)
		}
	}

	if rootDomain != "" && !IsSharedMailProvider(rootDomain) {
		if domContacts, err := r.lookupCached(ctx, "domain:"+rootDomain, func() ([]string, error) {
			return r.lookupTarget(ctx, "domain", rootDomain)
		}); err == nil {
			add(domContacts)
		}
	}

	return contacts, nil
}

func (r *Resolver) lookupCached(ctx context.Context, key string, fn func() ([]string, error)) ([]string, error) {
	if r.store != nil {
		if cached, ok, err := r.store.GetRDAPCache(key); err == nil && ok {
			return cached, nil
		}
	}
	res, err := fn()
	if err != nil {
		return nil, err
	}
	if r.store != nil {
		_ = r.store.SetRDAPCache(key, res, cacheTTL)
	}
	return res, nil
}

func (r *Resolver) lookupTarget(ctx context.Context, kind, value string) ([]string, error) {
	emails, err := r.queryRDAP(ctx, kind, value)
	if err == nil && len(emails) > 0 {
		return emails, nil
	}
	if r.whoisDial != nil {
		whoisEmails, wErr := r.lookupWHOIS(ctx, value)
		if wErr == nil && len(whoisEmails) > 0 {
			return whoisEmails, nil
		}
	}
	return emails, err
}

type rdapResponse struct {
	Entities []rdapEntity `json:"entities"`
}

type rdapEntity struct {
	Roles      []string     `json:"roles"`
	VCardArray []any        `json:"vcardArray"`
	Entities   []rdapEntity `json:"entities"`
}

func (r *Resolver) queryRDAP(ctx context.Context, kind, value string) ([]string, error) {
	endpoint := fmt.Sprintf("%s/%s/%s", strings.TrimRight(r.rdapBase, "/"), kind, value)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/rdap+json, application/json")
	resp, err := r.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("rdap HTTP %d", resp.StatusCode)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	if err != nil {
		return nil, err
	}
	var parsed rdapResponse
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return nil, err
	}

	var abuseEmails []string
	var fallbackEmails []string
	collectRDAPEmails(parsed.Entities, false, &abuseEmails, &fallbackEmails)
	if len(abuseEmails) > 0 {
		return dedupeEmails(abuseEmails), nil
	}
	return dedupeEmails(fallbackEmails), nil
}

func collectRDAPEmails(entities []rdapEntity, parentIsAbuse bool, abuseOut, fallbackOut *[]string) {
	for _, ent := range entities {
		isAbuse := parentIsAbuse
		for _, role := range ent.Roles {
			if strings.EqualFold(role, "abuse") {
				isAbuse = true
			}
		}
		emails := extractVCardEmails(ent.VCardArray)
		for _, em := range emails {
			if isAbuse || strings.HasPrefix(strings.ToLower(em), "abuse@") {
				*abuseOut = append(*abuseOut, em)
			} else {
				*fallbackOut = append(*fallbackOut, em)
			}
		}
		if len(ent.Entities) > 0 {
			collectRDAPEmails(ent.Entities, isAbuse, abuseOut, fallbackOut)
		}
	}
}

func extractVCardEmails(vcard []any) []string {
	if len(vcard) < 2 {
		return nil
	}
	props, ok := vcard[1].([]any)
	if !ok {
		return nil
	}
	var out []string
	for _, rawProp := range props {
		prop, ok := rawProp.([]any)
		if !ok || len(prop) < 4 {
			continue
		}
		name, _ := prop[0].(string)
		if !strings.EqualFold(name, "email") {
			continue
		}
		if val, ok := prop[3].(string); ok && val != "" {
			out = append(out, val)
		}
	}
	return out
}

func (r *Resolver) lookupWHOIS(ctx context.Context, query string) ([]string, error) {
	raw, err := r.whoisDial(ctx, "whois.iana.org:43", query)
	if err != nil {
		return nil, err
	}
	referred := ""
	scanner := bufio.NewScanner(strings.NewReader(raw))
	for scanner.Scan() {
		if m := whoisReferRegex.FindStringSubmatch(strings.TrimSpace(scanner.Text())); len(m) == 2 {
			referred = m[1]
			break
		}
	}
	if referred != "" {
		if !strings.Contains(referred, ":") {
			referred += ":43"
		}
		if next, err := r.whoisDial(ctx, referred, query); err == nil {
			raw = next
		}
	}

	var out []string
	for _, m := range whoisAbuseRegex.FindAllStringSubmatch(raw, -1) {
		if len(m) == 2 {
			out = append(out, m[1])
		}
	}
	if len(out) == 0 {
		out = append(out, genericAbuseRe.FindAllString(raw, -1)...)
	}
	return dedupeEmails(out), nil
}

func queryWHOISServer(ctx context.Context, server, query string) (string, error) {
	d := net.Dialer{Timeout: 5 * time.Second}
	conn, err := d.DialContext(ctx, "tcp", server)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := fmt.Fprintf(conn, "%s\r\n", query); err != nil {
		return "", err
	}
	raw, err := io.ReadAll(io.LimitReader(conn, 256<<10))
	if err != nil {
		return "", err
	}
	return string(raw), nil
}

func dedupeEmails(in []string) []string {
	seen := make(map[string]struct{})
	var out []string
	for _, raw := range in {
		clean := strings.ToLower(strings.Trim(strings.TrimSpace(raw), "<>.,;"))
		if !isValidEmail(clean) {
			continue
		}
		if _, ok := seen[clean]; ok {
			continue
		}
		seen[clean] = struct{}{}
		out = append(out, clean)
	}
	return out
}

func isValidEmail(addr string) bool {
	if addr == "" || !strings.Contains(addr, "@") {
		return false
	}
	parsed, err := mail.ParseAddress(addr)
	return err == nil && parsed.Address != ""
}
