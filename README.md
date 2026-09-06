# DNSMint for libdns

[![Go Reference](https://pkg.go.dev/badge/github.com/dnsmint/libdns-dnsmint)](https://pkg.go.dev/github.com/dnsmint/libdns-dnsmint)

A [libdns](https://github.com/libdns/libdns) provider that publishes ACME DNS-01 challenges for [DNSMint](https://dnsmint.com) hostnames. It is what the [Caddy module](https://github.com/dnsmint/caddy-dnsmint) is built on.

DNSMint operates the domains its hostnames live on and manages every record in them, so the only records you publish directly are `_acme-challenge` TXT records. This package implements `libdns.RecordAppender` and `libdns.RecordDeleter` for those and nothing else. That is the whole of what [certmagic](https://github.com/caddyserver/certmagic) needs; `GetRecords` and `SetRecords` are deliberately absent rather than approximated.

## Configuration

```go
provider := dnsmint.Provider{
	APIKey: os.Getenv("DNSMINT_API_KEY"),
}
```

| Field | JSON | Description |
|---|---|---|
| `APIKey` | `api_key` | A DNSMint API key with the `dns01:write` scope. Narrow it to the hostname or domain the machine renews for. |
| `APIURL` | `api_url` | API base URL. Defaults to `https://dnsmint.com/api`. |
| `HTTPClient` | – | Optional `*http.Client`. Defaults to one with a 30s timeout. |

No environment variables are read. The record name must be `_acme-challenge` under a hostname the key can reach; the hostname itself is derived server-side from the challenge name.

## API

The two calls map onto DNSMint's [`/httpreq/present` and `/httpreq/cleanup`](https://dnsmint.com/api-reference#httpreq-present) endpoints, the same ones lego's `httpreq` provider uses.

## Testing

```sh
go test ./...
```

The tests run against an in-process HTTP server; no account is needed.

## Support

Something not working, or a case this does not cover? Open an issue here, or
write to [hello@dnsmint.com](mailto:hello@dnsmint.com). This package is
maintained by the DNSMint team.
