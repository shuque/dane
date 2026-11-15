package dane

import (
	"bytes"
	"crypto/x509"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Role says which side of the TLS connection is being authenticated.
//
// The zero value is RoleServer; client-authentication callers must set
// RoleClient explicitly.
type Role int

const (
	RoleServer Role = 0
	RoleClient Role = 1
)

// VerifyOptions controls Verify.
type VerifyOptions struct {
	Role             Role
	Name             string         // reference identity: ClientName (client role) or server hostname (server role)
	AllowedUsages    []Usage        // nil = all four usages; empty non-nil = none (fails closed)
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
	// Depth locates the matched cert. DANE-TA: index in the presented
	// chain (1 for a "2 0 0" cert taken from the record). PKIX-TA: index
	// in the verified chain (may be a pool root). EE usages: 0. -1 if none.
	Depth  int
	Detail string // human-readable reason
	Err    error  // typed cause for StatusFailed (e.g. ErrNameMismatch); nil otherwise
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
		if rec.Status == StatusFailed && errors.Is(rec.Err, ErrNameMismatch) {
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
	case DANETA:
		verifyDANETA(rec, chain, opts)
	case PKIXEE:
		verifyPKIXEE(rec, chain, opts)
	case PKIXTA:
		verifyPKIXTA(rec, chain, opts)
	default:
		rec.Status = StatusNoMatch
		rec.Detail = "unknown usage"
	}
}

func fail(rec *RecordResult, err error, detail string) {
	rec.Status = StatusFailed
	rec.Depth = -1
	rec.Err = err
	rec.Detail = detail
}

func dataMatches(rec *RecordResult, c *x509.Certificate) bool {
	d, err := ComputeData(rec.Record.Selector, rec.Record.MatchingType, c)
	return err == nil && bytes.Equal(d, rec.Record.Data)
}

func ekuFor(role Role) []x509.ExtKeyUsage {
	if role == RoleClient {
		return []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	}
	return []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
}

func intermediates(chain []*x509.Certificate) *x509.CertPool {
	p := x509.NewCertPool()
	for _, c := range chain[1:] {
		if c != nil {
			p.AddCert(c)
		}
	}
	return p
}

// checkName applies the role's reference-identity check to the EE cert.
func checkName(ee *x509.Certificate, opts VerifyOptions) error {
	if opts.Role == RoleClient {
		want := strings.TrimSuffix(opts.Name, ".")
		if !validClientName(want) {
			return fmt.Errorf("%w: invalid client name %q", ErrNameMismatch, want)
		}
		for _, n := range ee.DNSNames {
			if asciiEqualFold(n, want) {
				return nil
			}
		}
		return fmt.Errorf("%w: %q not in certificate SANs", ErrNameMismatch, want)
	}
	if err := ee.VerifyHostname(opts.Name); err != nil {
		return fmt.Errorf("%w: %v", ErrNameMismatch, err)
	}
	return nil
}

// validClientName reports whether name (one trailing dot already
// removed) is non-empty, has no empty label, and uses only [A-Za-z0-9_.-].
func validClientName(name string) bool {
	if name == "" {
		return false
	}
	prev := byte('.')
	for i := 0; i < len(name); i++ {
		c := name[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '_', c == '-':
		case c == '.':
			if prev == '.' {
				return false
			}
		default:
			return false
		}
		prev = c
	}
	return prev != '.'
}

// asciiEqualFold compares a and b folding only ASCII A-Z.
func asciiEqualFold(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		x, y := a[i], b[i]
		if x >= 'A' && x <= 'Z' {
			x += 'a' - 'A'
		}
		if y >= 'A' && y <= 'Z' {
			y += 'a' - 'A'
		}
		if x != y {
			return false
		}
	}
	return true
}

// nameCheckOutcome finishes a record whose data and chain checks passed.
func nameCheckOutcome(rec *RecordResult, ee *x509.Certificate, depth int, opts VerifyOptions, what string) {
	if err := checkName(ee, opts); err != nil {
		fail(rec, err, what+" matched but name check failed: "+err.Error())
		return
	}
	rec.Status = StatusMatched
	rec.Depth = depth
	rec.Detail = what + " match"
}

func verifyDANETA(rec *RecordResult, chain []*x509.Certificate, opts VerifyOptions) {
	type cand struct {
		cert  *x509.Certificate
		depth int
	}
	var cands []cand
	for i := 1; i < len(chain); i++ {
		if chain[i] != nil && dataMatches(rec, chain[i]) {
			cands = append(cands, cand{chain[i], i})
		}
	}
	if len(cands) == 0 && rec.Record.Selector == SelectorCert && rec.Record.MatchingType == MatchFull {
		// RFC 7671 section 5.2: a 2 0 0 TA need not be in the presented chain.
		// The record's cert is then the sole root; if the EE cert is
		// self-signed this may be the EE cert itself.
		if c, err := x509.ParseCertificate(rec.Record.Data); err == nil {
			cands = append(cands, cand{c, 1})
		}
	}
	if len(cands) == 0 {
		rec.Status = StatusNoMatch
		rec.Detail = "no trust anchor in chain matches"
		return
	}
	inter := intermediates(chain)
	var lastErr error
	for _, c := range cands {
		roots := x509.NewCertPool()
		roots.AddCert(c.cert)
		_, err := chain[0].Verify(x509.VerifyOptions{
			Roots:         roots,
			Intermediates: inter,
			KeyUsages:     ekuFor(opts.Role),
			CurrentTime:   opts.CurrentTime,
		})
		if err != nil {
			lastErr = err
			continue
		}
		nameCheckOutcome(rec, chain[0], c.depth, opts, "DANE-TA")
		return
	}
	fail(rec, lastErr, "DANE-TA data matched but chain verification failed: "+lastErr.Error())
}

// pkixChains runs PKIX validation of the EE cert; the error is non-nil on failure.
func pkixChains(chain []*x509.Certificate, opts VerifyOptions) ([][]*x509.Certificate, error) {
	roots := opts.Roots
	if roots == nil {
		var err error
		if roots, err = x509.SystemCertPool(); err != nil {
			return nil, fmt.Errorf("loading system roots: %w", err)
		}
	}
	return chain[0].Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates(chain),
		KeyUsages:     ekuFor(opts.Role),
		CurrentTime:   opts.CurrentTime,
	})
}

func verifyPKIXEE(rec *RecordResult, chain []*x509.Certificate, opts VerifyOptions) {
	if !dataMatches(rec, chain[0]) {
		rec.Status = StatusNoMatch
		rec.Detail = "EE certificate data does not match"
		return
	}
	if _, err := pkixChains(chain, opts); err != nil {
		fail(rec, err, "PKIX-EE data matched but PKIX validation failed: "+err.Error())
		return
	}
	nameCheckOutcome(rec, chain[0], 0, opts, "PKIX-EE")
}

func verifyPKIXTA(rec *RecordResult, chain []*x509.Certificate, opts VerifyOptions) {
	// Cheap pre-check so non-matching records do not need a PKIX run.
	anyMatch := false
	for i := 1; i < len(chain); i++ {
		if chain[i] != nil && dataMatches(rec, chain[i]) {
			anyMatch = true
		}
	}
	chains, err := pkixChains(chain, opts)
	if err != nil {
		if anyMatch {
			fail(rec, err, "PKIX-TA data matched but PKIX validation failed: "+err.Error())
		} else {
			// Data may match a pool root we cannot see, but PKIX failed anyway.
			rec.Status = StatusNoMatch
			rec.Detail = "PKIX validation failed: " + err.Error()
		}
		return
	}
	for _, vc := range chains {
		for i := 1; i < len(vc); i++ {
			if dataMatches(rec, vc[i]) {
				nameCheckOutcome(rec, chain[0], i, opts, "PKIX-TA")
				return
			}
		}
	}
	rec.Status = StatusNoMatch
	rec.Detail = "no certificate in the validated chain matches"
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
