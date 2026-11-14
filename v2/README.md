# github.com/shuque/dane/v2

Application-neutral DANE (RFC 6698, RFC 7671) TLSA lookup and certificate
verification in Go, for both server and client authentication (including
draft-ietf-dance-client-auth). It does two things:

1. `Resolver.LookupTLSA` fetches TLSA records through a validating resolver.
2. `Verify` checks a certificate chain against those records.

The library never dials TLS. `Verify` takes a `[]*x509.Certificate`, so it
works with any TLS stack or version. Requiring TLS 1.3, as the client-auth
draft does, is the application's job.

## Usage

```go
res := dane.NewResolver("127.0.0.1:53")
rrset, err := res.LookupTLSA(ctx, "_smtp._client.mta1.example.com")
if err != nil { /* *LookupError; see below */ }
result, err := dane.Verify(chain, rrset, dane.VerifyOptions{
	Role: dane.RoleClient,
	Name: "_smtp._client.mta1.example.com",
})
```

See `example_test.go`. For servers, `dane.ServiceName(443, "tcp", host)`
builds the owner name `_443._tcp.host.`. `ResolverFromConf("")` reads
`/etc/resolv.conf`.

## Trust model

Queries set RD=1, AD=1 and EDNS0 DO=1, with a UDP payload of default 1232 (`Resolver.Payload`). A
truncated (TC=1) UDP response is retried over TCP. The library does not
validate DNSSEC itself. It trusts the AD bit in the response from the
configured resolver, so that resolver must be a validating one and the path
to it must be trusted (for example, a resolver on localhost).

## Roles

`VerifyOptions.Role` selects `RoleServer` (the zero value, so client callers must set `RoleClient` explicitly) or `RoleClient`.

| | RoleServer | RoleClient |
|---|---|---|
| EKU required (PKIX/DANE-TA chain checks) | serverAuth | clientAuth |
| `Name` is | server hostname | ClientName |
| Name check | `x509.VerifyHostname` (wildcards allowed) | SAN dNSName equals `Name` exactly, ASCII case-insensitive, ignoring one trailing dot; no wildcards. A `Name` with bytes outside `[A-Za-z0-9_.-]` or an empty label always fails |

DANE-EE (usage 3) does no name check and no expiry check (RFC 7671 s5.1):
a matching end-entity certificate is enough. The other usages (PKIX-TA,
PKIX-EE, DANE-TA) apply the role's name check to the end-entity
certificate, and PKIX validation or chain building as appropriate.

Other `VerifyOptions`: `AllowedUsages` (nil means all four), `Roots` (PKIX
roots for usages 0 and 1; nil means the system pool), `DigestPreference`
(default SHA-512 then SHA-256; weaker digests are skipped when a preferred
one exists for the same usage and selector), and `CurrentTime`.

`Verify` evaluates every record and returns a `*Result` with a per-record
`RecordResult` (status matched, no match, failed or skipped, plus detail).
On failure the error wraps `ErrNotAuthenticated`, and also
`ErrNameMismatch` if a record's data matched but only the name check
failed. An empty chain returns `ErrNoChain`.

## Lookup errors

`LookupTLSA` always returns a `*LookupError` (fields `Qname`, `Rcode`,
`NegTTL`, `Err`), matched with `errors.Is` against the sentinels:

| DNS outcome | Error |
|---|---|
| Authenticated answer with TLSA records (CNAMEs followed, up to 8) | none |
| Any answer or NXDOMAIN with AD=0 (including an insecure denial) | `ErrInsecure` |
| NXDOMAIN with AD=1 | `ErrNXDOMAIN` (`NegTTL` set from the SOA) |
| NOERROR, AD=1, no TLSA records at the end of the alias chain | `ErrNoData` (`NegTTL` set) |
| SERVFAIL, REFUSED or any other rcode (includes DNSSEC bogus) | `ErrServFail` |
| Transport error (no response from any server) | `ErrServFail` |
| Timeout, context deadline or cancellation | `ErrTimeout` |

An insecure denial is `ErrInsecure`, never `ErrNXDOMAIN` or `ErrNoData`: the
AD check comes first, so an unauthenticated "no such record" cannot be
mistaken for proof of absence. Transport causes stay reachable through
`errors.Is`/`errors.As` (for example `context.DeadlineExceeded`).

`RRset` holds `Qname`, `Owner` (end of the alias chain), `Aliases`, `TTL`
(minimum over the TLSA RRs and CNAMEs) and `Records`, which includes unusable
records so that `Verify` can report them as skipped.

## Removed from v1

- `ConnectByName*` and other connection helpers (the library never dials).
- STARTTLS support (`starttls.go`).
- `http.go` helpers.
- Address (A/AAAA) lookup.
- The monolithic `Config` struct, replaced by `Resolver`, `VerifyOptions`
  and the `RRset`/`Result` types.

## Testing

`go test ./...` runs offline unit tests using an in-process DNS server and
generated certificates. `danetest/` has certificate generators and an in-process UDP/TCP fake DNS server for tests.
