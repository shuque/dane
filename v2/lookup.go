package dane

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/miekg/dns"
)

// RRset is the result of a successful, DNSSEC-authenticated TLSA lookup.
type RRset struct {
	Qname   string   // as queried, FQDN, lowercased
	Owner   string   // owner of the TLSA RRs (end of the alias chain)
	Aliases []string // CNAME targets followed, in order
	TTL     uint32   // min TTL over the TLSA RRs and the CNAMEs used
	Records []TLSA   // every TLSA RR at Owner, including unusable ones
}

// Lookup failure classes, matched with errors.Is.
var (
	ErrInsecure = errors.New("dane: response not DNSSEC authenticated")
	ErrNXDOMAIN = errors.New("dane: name does not exist")
	ErrNoData   = errors.New("dane: no TLSA records")
	ErrServFail = errors.New("dane: DNS lookup failed") // SERVFAIL, REFUSED, other rcodes, bogus
	ErrTimeout  = errors.New("dane: DNS lookup timed out")
)

// LookupError is the error type returned by LookupTLSA.
type LookupError struct {
	Qname  string
	Rcode  int    // -1 if no response
	NegTTL uint32 // authenticated NXDOMAIN/NODATA: min(SOA TTL, SOA MINIMUM); else 0
	Err    error  // one of the sentinels above
	cause  error  // transport error, if any
}

func (e *LookupError) Error() string {
	s := fmt.Sprintf("%v (qname %s, rcode %d)", e.Err, e.Qname, e.Rcode)
	if e.cause != nil {
		s += ": " + e.cause.Error()
	}
	return s
}

// Unwrap returns the sentinel and the transport error, if any.
func (e *LookupError) Unwrap() []error {
	if e.cause != nil {
		return []error{e.Err, e.cause}
	}
	return []error{e.Err}
}

const maxCNAMEHops = 8

// LookupTLSA queries for TLSA records at qname via a validating
// resolver, following CNAMEs in the answer. DNAME is handled via the
// CNAME that the validating resolver synthesizes. Any error is a *LookupError.
func (r *Resolver) LookupTLSA(ctx context.Context, qname string) (*RRset, error) {
	qname = dns.CanonicalName(qname)
	fail := func(rcode int, neg uint32, sentinel, cause error) error {
		return &LookupError{Qname: qname, Rcode: rcode, NegTTL: neg, Err: sentinel, cause: cause}
	}

	resp, err := r.Exchange(ctx, qname, dns.TypeTLSA)
	if err != nil {
		var ne net.Error
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) ||
			(errors.As(err, &ne) && ne.Timeout()) {
			return nil, fail(-1, 0, ErrTimeout, err)
		}
		return nil, fail(-1, 0, ErrServFail, err)
	}
	if resp.Rcode != dns.RcodeSuccess && resp.Rcode != dns.RcodeNameError {
		return nil, fail(resp.Rcode, 0, ErrServFail, nil)
	}
	if len(resp.Question) != 1 || dns.CanonicalName(resp.Question[0].Name) != qname ||
		resp.Question[0].Qtype != dns.TypeTLSA {
		return nil, fail(resp.Rcode, 0, ErrServFail, errors.New("response question does not match query"))
	}

	if !resp.AuthenticatedData {
		return nil, fail(resp.Rcode, 0, ErrInsecure, nil)
	}
	if resp.Rcode == dns.RcodeNameError {
		return nil, fail(resp.Rcode, negTTL(resp), ErrNXDOMAIN, nil)
	}

	set := &RRset{Qname: qname, Owner: qname}
	set.TTL = ^uint32(0)
	seen := map[string]bool{qname: true}
	for {
		var next string
		for _, rr := range resp.Answer {
			if c, ok := rr.(*dns.CNAME); ok && dns.CanonicalName(c.Hdr.Name) == set.Owner {
				next = dns.CanonicalName(c.Target)
				set.TTL = min(set.TTL, c.Hdr.Ttl)
				break
			}
		}
		if next == "" {
			break
		}
		if seen[next] || len(set.Aliases) >= maxCNAMEHops {
			return nil, fail(resp.Rcode, 0, ErrServFail, errors.New("CNAME loop or chain too long"))
		}
		seen[next] = true
		set.Aliases = append(set.Aliases, next)
		set.Owner = next
	}

	for _, rr := range resp.Answer {
		t, ok := rr.(*dns.TLSA)
		if !ok || dns.CanonicalName(t.Hdr.Name) != set.Owner {
			continue
		}
		set.Records = append(set.Records, tlsaFromRR(t))
		set.TTL = min(set.TTL, t.Hdr.Ttl)
	}
	if len(set.Records) == 0 {
		return nil, fail(resp.Rcode, negTTL(resp), ErrNoData, nil)
	}
	return set, nil
}

// tlsaFromRR converts a wire TLSA RR. Undecodable hex yields a record
// with nil Data (unusable) rather than failing the lookup.
func tlsaFromRR(t *dns.TLSA) TLSA {
	data, err := hex.DecodeString(t.Certificate)
	if err != nil {
		data = nil
	}
	return TLSA{
		Usage:        Usage(t.Usage),
		Selector:     Selector(t.Selector),
		MatchingType: MatchingType(t.MatchingType),
		Data:         data,
	}
}

// negTTL returns min(SOA TTL, SOA MINIMUM) from the authority section.
func negTTL(resp *dns.Msg) uint32 {
	for _, rr := range resp.Ns {
		if soa, ok := rr.(*dns.SOA); ok {
			return min(soa.Hdr.Ttl, soa.Minttl)
		}
	}
	return 0
}

// ServiceName returns the TLSA owner name _port._proto.host. (lowercased FQDN).
func ServiceName(port int, proto, host string) string {
	return "_" + strconv.Itoa(port) + "._" + strings.ToLower(proto) + "." + dns.CanonicalName(host)
}
