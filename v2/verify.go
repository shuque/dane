package dane

import (
	"bytes"
	"crypto/x509"
	"errors"
	"fmt"
	"time"
)

// Role says which side of the TLS connection is being authenticated.
type Role int

const (
	RoleServer Role = 0
	RoleClient Role = 1
)

// VerifyOptions controls Verify.
type VerifyOptions struct {
	Role             Role
	Name             string         // reference identity: ClientName (client role) or server hostname (server role)
	AllowedUsages    []Usage        // nil = all four
	Roots            *x509.CertPool // PKIX roots for usages 0/1; nil = x509.SystemCertPool()
	DigestPreference []MatchingType // strongest first; nil = [MatchSHA512, MatchSHA256]
	CurrentTime      time.Time      // zero = time.Now()
}

// RecordStatus is the outcome of evaluating one TLSA record.
type RecordStatus int

const (
	StatusMatched RecordStatus = iota // record authenticated the chain
	StatusNoMatch                     // association data did not match
	StatusFailed                      // data matched, but a PKIX/chain/name check failed
	StatusSkipped                     // filtered out before matching
)

func (s RecordStatus) String() string {
	switch s {
	case StatusMatched:
		return "matched"
	case StatusNoMatch:
		return "nomatch"
	case StatusFailed:
		return "failed"
	case StatusSkipped:
		return "skipped"
	}
	return fmt.Sprintf("RecordStatus(%d)", int(s))
}

// RecordResult is the evaluation of a single TLSA record.
type RecordResult struct {
	Record TLSA
	Status RecordStatus
	Depth  int    // chain depth of the matched cert (0 = EE); -1 if none
	Detail string // human-readable reason
	err    error  // cause for StatusFailed (e.g. ErrNameMismatch)
}

// Result is the outcome of Verify.
type Result struct {
	Authenticated bool
	Matched       *RecordResult  // first record with StatusMatched, in RRset order
	Records       []RecordResult // one per RRset record, same order
}

var (
	ErrNoChain          = errors.New("dane: empty certificate chain")
	ErrNotAuthenticated = errors.New("dane: no TLSA record matched")
	ErrNameMismatch     = errors.New("dane: certificate does not contain the reference name")
)

var defaultDigestPreference = []MatchingType{MatchSHA512, MatchSHA256}

// Verify evaluates every record (no short-circuit, for diagnostics).
// It returns (result, nil) when authenticated. Otherwise it returns
// (result, err): err wraps ErrNotAuthenticated, and also wraps
// ErrNameMismatch when a record's data matched but only the name check
// failed.
func Verify(chain []*x509.Certificate, rrset *RRset, opts VerifyOptions) (*Result, error) {
	if len(chain) == 0 || chain[0] == nil {
		return nil, ErrNoChain
	}
	res := &Result{}
	if rrset == nil || len(rrset.Records) == 0 {
		return res, fmt.Errorf("%w: no TLSA records", ErrNotAuthenticated)
	}
	res.Records = make([]RecordResult, len(rrset.Records))
	for i, r := range rrset.Records {
		res.Records[i] = RecordResult{Record: r, Status: StatusNoMatch, Depth: -1}
	}
	filterRecords(res.Records, opts)

	nameMismatch := false
	for i := range res.Records {
		rec := &res.Records[i]
		if rec.Status == StatusSkipped {
			continue
		}
		evalRecord(rec, chain, opts)
		if rec.Status == StatusMatched && res.Matched == nil {
			res.Matched = rec
		}
		if rec.Status == StatusFailed && errors.Is(rec.err, ErrNameMismatch) {
			nameMismatch = true
		}
	}
	if res.Matched != nil {
		res.Authenticated = true
		return res, nil
	}
	if nameMismatch {
		return res, fmt.Errorf("%w: %w", ErrNotAuthenticated, ErrNameMismatch)
	}
	return res, ErrNotAuthenticated
}

func skip(r *RecordResult, why string) {
	r.Status = StatusSkipped
	r.Detail = "skipped: " + why
}

// filterRecords applies usability, allowed-usage and digest-agility filtering.
func filterRecords(recs []RecordResult, opts VerifyOptions) {
	pref := opts.DigestPreference
	if pref == nil {
		pref = defaultDigestPreference
	}
	type group struct {
		u Usage
		s Selector
	}
	best := map[group]int{} // best preference rank present in each group
	rank := func(m MatchingType) int {
		for i, p := range pref {
			if p == m {
				return i
			}
		}
		return -1
	}
	for i := range recs {
		r := &recs[i]
		if !r.Record.Usable() {
			skip(r, "unusable")
			continue
		}
		if opts.AllowedUsages != nil && !usageAllowed(opts.AllowedUsages, r.Record.Usage) {
			skip(r, "usage not allowed")
			continue
		}
		if r.Record.MatchingType == MatchFull {
			continue
		}
		k := rank(r.Record.MatchingType)
		if k < 0 {
			skip(r, "unsupported digest")
			continue
		}
		g := group{r.Record.Usage, r.Record.Selector}
		if b, ok := best[g]; !ok || k < b {
			best[g] = k
		}
	}
	for i := range recs {
		r := &recs[i]
		if r.Status == StatusSkipped || r.Record.MatchingType == MatchFull {
			continue
		}
		g := group{r.Record.Usage, r.Record.Selector}
		if rank(r.Record.MatchingType) != best[g] {
			skip(r, "weaker digest than preferred digest present")
		}
	}
}

func usageAllowed(allowed []Usage, u Usage) bool {
	for _, a := range allowed {
		if a == u {
			return true
		}
	}
	return false
}

// evalRecord dispatches on usage.
func evalRecord(rec *RecordResult, chain []*x509.Certificate, opts VerifyOptions) {
	switch rec.Record.Usage {
	case DANEEE:
		verifyDANEEE(rec, chain[0])
	default: // PKIXTA, PKIXEE, DANETA: implemented in a later task
		rec.Status = StatusNoMatch
		rec.Detail = "not implemented"
	}
}

// verifyDANEEE: match the EE cert only; no name or validity checks (RFC 7671 §5.1).
func verifyDANEEE(rec *RecordResult, ee *x509.Certificate) {
	d, err := ComputeData(rec.Record.Selector, rec.Record.MatchingType, ee)
	if err == nil && bytes.Equal(d, rec.Record.Data) {
		rec.Status = StatusMatched
		rec.Depth = 0
		rec.Detail = "DANE-EE match"
		return
	}
	rec.Status = StatusNoMatch
	rec.Detail = "EE certificate data does not match"
}
