package dnsmint

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/libdns/libdns"
)

const (
	zone  = "dnsmint-a3f9c1.dev."
	value = "LHDhK3oGRvkiefQnx7OOczTY5Tic_xZ6HcMOc_gmtoM"
)

var challenge = libdns.TXT{Name: "_acme-challenge.q7k4m2", Text: value}

type call struct {
	Path, Auth  string
	FQDN, Value string
}

// server records every request and answers with the given status and body.
func server(t *testing.T, status int, body string) (*httptest.Server, *[]call) {
	var calls []call
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var msg struct {
			FQDN  string `json:"fqdn"`
			Value string `json:"value"`
		}
		if err := json.NewDecoder(r.Body).Decode(&msg); err != nil {
			t.Errorf("decode body: %v", err)
		}
		calls = append(calls, call{r.URL.Path, r.Header.Get("Authorization"), msg.FQDN, msg.Value})
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv, &calls
}

func TestPresentAndCleanup(t *testing.T) {
	for _, tc := range []struct {
		name string
		do   func(*Provider, context.Context) ([]libdns.Record, error)
		path string
	}{
		{"append", func(p *Provider, ctx context.Context) ([]libdns.Record, error) {
			return p.AppendRecords(ctx, zone, []libdns.Record{challenge})
		}, "/httpreq/present"},
		{"delete", func(p *Provider, ctx context.Context) ([]libdns.Record, error) {
			return p.DeleteRecords(ctx, zone, []libdns.Record{challenge})
		}, "/httpreq/cleanup"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv, calls := server(t, http.StatusOK, `{}`)
			// Trailing slash on the base URL must not produce a double slash.
			p := &Provider{APIKey: "dnsm_key", APIURL: srv.URL + "/"}

			recs, err := tc.do(p, context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if len(recs) != 1 || recs[0] != challenge {
				t.Fatalf("returned %#v, want the input TXT", recs)
			}
			want := call{tc.path, "Bearer dnsm_key", "_acme-challenge.q7k4m2." + zone, value}
			if len(*calls) != 1 || (*calls)[0] != want {
				t.Fatalf("calls %#v, want %#v", *calls, want)
			}
		})
	}
}

func TestRejectsOtherRecords(t *testing.T) {
	srv, calls := server(t, http.StatusOK, `{}`)
	p := &Provider{APIKey: "dnsm_key", APIURL: srv.URL}

	for _, rec := range []libdns.Record{
		libdns.TXT{Name: "q7k4m2", Text: value},
		libdns.RR{Name: "_acme-challenge.q7k4m2", Type: "A", Data: "10.0.0.1"},
	} {
		if _, err := p.AppendRecords(context.Background(), zone, []libdns.Record{rec}); err == nil {
			t.Errorf("%#v accepted, want an error", rec)
		}
	}
	if len(*calls) != 0 {
		t.Fatalf("server called %d times for rejected records", len(*calls))
	}
}

func TestAPIErrorIsSurfaced(t *testing.T) {
	srv, _ := server(t, http.StatusForbidden, `{"error":"This API key's \"dns01:write\" scope is limited to other.dnsmint-a3f9c1.dev","code":"FORBIDDEN"}`)
	p := &Provider{APIKey: "dnsm_key", APIURL: srv.URL}

	_, err := p.AppendRecords(context.Background(), zone, []libdns.Record{challenge})
	if err == nil {
		t.Fatal("no error for HTTP 403")
	}
	for _, want := range []string{"HTTP 403", "scope is limited to other.dnsmint-a3f9c1.dev"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q lacks %q", err, want)
		}
	}
}
