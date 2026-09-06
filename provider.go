// Package dnsmint implements a libdns provider for DNSMint (https://dnsmint.com).
//
// DNSMint operates the domains its hostnames live on and manages every record
// in them, so the only records a customer publishes directly are ACME DNS-01
// challenges. This provider appends and deletes _acme-challenge TXT records and
// nothing else, which is what certmagic and Caddy need for DNS-01.
package dnsmint

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/libdns/libdns"
)

const (
	defaultAPIURL  = "https://dnsmint.com/api"
	challengeLabel = "_acme-challenge"
)

// Provider publishes DNS-01 challenges for DNSMint hostnames.
type Provider struct {
	// APIKey is a DNSMint API key with the dns01:write scope. It may be
	// narrowed to one hostname or one domain.
	APIKey string `json:"api_key,omitempty"`

	// APIURL is the API base URL. Defaults to https://dnsmint.com/api.
	APIURL string `json:"api_url,omitempty"`

	// HTTPClient makes the API calls. Defaults to a client with a 30s timeout.
	HTTPClient *http.Client `json:"-"`
}

// AppendRecords publishes _acme-challenge TXT records. Any other record is
// rejected, since DNSMint manages the rest of the zone.
func (p *Provider) AppendRecords(ctx context.Context, zone string, recs []libdns.Record) ([]libdns.Record, error) {
	return p.each(ctx, zone, recs, "present")
}

// DeleteRecords withdraws _acme-challenge TXT records published earlier.
func (p *Provider) DeleteRecords(ctx context.Context, zone string, recs []libdns.Record) ([]libdns.Record, error) {
	return p.each(ctx, zone, recs, "cleanup")
}

func (p *Provider) each(ctx context.Context, zone string, recs []libdns.Record, action string) ([]libdns.Record, error) {
	var done []libdns.Record
	for _, rec := range recs {
		rr := rec.RR()
		fqdn := libdns.AbsoluteName(rr.Name, zone)
		if rr.Type != "TXT" || !strings.HasPrefix(fqdn, challengeLabel+".") {
			return done, fmt.Errorf("dnsmint: only %s TXT records can be published, not %s %s", challengeLabel, rr.Type, fqdn)
		}
		if err := p.post(ctx, action, fqdn, rr.Data); err != nil {
			return done, err
		}
		done = append(done, libdns.TXT{Name: rr.Name, TTL: rr.TTL, Text: rr.Data})
	}
	return done, nil
}

// post calls DNSMint's httpreq-shaped endpoints, which take the challenge FQDN
// and value and derive the hostname server-side.
func (p *Provider) post(ctx context.Context, action, fqdn, value string) error {
	body, err := json.Marshal(struct {
		FQDN  string `json:"fqdn"`
		Value string `json:"value"`
	}{fqdn, value})
	if err != nil {
		return err
	}

	apiURL := p.APIURL
	if apiURL == "" {
		apiURL = defaultAPIURL
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimSuffix(apiURL, "/")+"/httpreq/"+action, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+p.APIKey)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	client := p.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("dnsmint: %s: %w", action, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode/100 == 2 {
		return nil
	}
	// The API answers errors as {"error": "...", "code": "..."}; surface the
	// message so a narrowed key or a missing hostname is diagnosable from Caddy's log.
	var apiErr struct {
		Error string `json:"error"`
	}
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	_ = json.Unmarshal(raw, &apiErr)
	if apiErr.Error == "" {
		apiErr.Error = strings.TrimSpace(string(raw))
	}
	return fmt.Errorf("dnsmint: %s %s: HTTP %d: %s", action, fqdn, resp.StatusCode, apiErr.Error)
}

// Interface guards
var (
	_ libdns.RecordAppender = (*Provider)(nil)
	_ libdns.RecordDeleter  = (*Provider)(nil)
)
