package dane

import (
	"crypto/x509"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/shuque/dane/v2/danetest"
)

func rrs(recs ...TLSA) *RRset { return &RRset{Records: recs} }

func mustTLSA(t *testing.T, u Usage, s Selector, m MatchingType, c *x509.Certificate) TLSA {
	t.Helper()
	r, err := NewTLSA(u, s, m, c)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func wrong(m MatchingType) []byte {
	n := 32
	if m == MatchSHA512 {
		n = 64
	}
	return make([]byte, n)
}

func TestDANEEEMatch(t *testing.T) {
	c, _ := danetest.NewSelfSigned(t, danetest.CertOpts{DNSNames: []string{"a.example"}})
	res, err := Verify([]*x509.Certificate{c}, rrs(mustTLSA(t, DANEEE, SelectorSPKI, MatchSHA256, c)), VerifyOptions{Role: RoleClient, Name: "x"})
	if err != nil || !res.Authenticated || res.Matched == nil || res.Matched.Depth != 0 {
		t.Fatalf("res=%+v err=%v", res, err)
	}
}

func TestDANEEEExpiredOK(t *testing.T) {
	c, _ := danetest.NewSelfSigned(t, danetest.CertOpts{
		NotBefore: time.Now().Add(-48 * time.Hour), NotAfter: time.Now().Add(-24 * time.Hour)})
	res, err := Verify([]*x509.Certificate{c}, rrs(mustTLSA(t, DANEEE, SelectorSPKI, MatchSHA256, c)), VerifyOptions{})
	if err != nil || !res.Authenticated {
		t.Fatalf("res=%+v err=%v", res, err)
	}
}

func TestDANEEENoMatch(t *testing.T) {
	c, _ := danetest.NewSelfSigned(t, danetest.CertOpts{})
	o, _ := danetest.NewSelfSigned(t, danetest.CertOpts{})
	res, err := Verify([]*x509.Certificate{c}, rrs(mustTLSA(t, DANEEE, SelectorSPKI, MatchSHA256, o)), VerifyOptions{})
	if !errors.Is(err, ErrNotAuthenticated) || res.Authenticated || res.Records[0].Status != StatusNoMatch {
		t.Fatalf("res=%+v err=%v", res, err)
	}
}

func TestDigestAgility(t *testing.T) {
	c, _ := danetest.NewSelfSigned(t, danetest.CertOpts{})
	res, err := Verify([]*x509.Certificate{c}, rrs(
		TLSA{DANEEE, SelectorSPKI, MatchSHA256, wrong(MatchSHA256)},
		mustTLSA(t, DANEEE, SelectorSPKI, MatchSHA512, c)), VerifyOptions{})
	if err != nil || !res.Authenticated {
		t.Fatalf("res=%+v err=%v", res, err)
	}
	if res.Records[0].Status != StatusSkipped || !strings.Contains(res.Records[0].Detail, "weaker digest") {
		t.Fatalf("rec0=%+v", res.Records[0])
	}
}

func TestDigestAgilityRejectsWeakOnly(t *testing.T) {
	c, _ := danetest.NewSelfSigned(t, danetest.CertOpts{})
	res, err := Verify([]*x509.Certificate{c}, rrs(
		mustTLSA(t, DANEEE, SelectorSPKI, MatchSHA256, c),
		TLSA{DANEEE, SelectorSPKI, MatchSHA512, wrong(MatchSHA512)}), VerifyOptions{})
	if !errors.Is(err, ErrNotAuthenticated) || res.Authenticated {
		t.Fatalf("res=%+v err=%v", res, err)
	}
}

func TestDigestAgilityFullAlwaysKept(t *testing.T) {
	c, _ := danetest.NewSelfSigned(t, danetest.CertOpts{})
	res, err := Verify([]*x509.Certificate{c}, rrs(
		mustTLSA(t, DANEEE, SelectorSPKI, MatchFull, c),
		TLSA{DANEEE, SelectorSPKI, MatchSHA512, wrong(MatchSHA512)}), VerifyOptions{})
	if err != nil || !res.Authenticated {
		t.Fatalf("res=%+v err=%v", res, err)
	}
}

func TestAllowedUsages(t *testing.T) {
	c, _ := danetest.NewSelfSigned(t, danetest.CertOpts{})
	res, err := Verify([]*x509.Certificate{c}, rrs(mustTLSA(t, DANEEE, SelectorSPKI, MatchSHA256, c)),
		VerifyOptions{AllowedUsages: []Usage{DANETA}})
	if !errors.Is(err, ErrNotAuthenticated) || res.Records[0].Status != StatusSkipped {
		t.Fatalf("res=%+v err=%v", res, err)
	}
}

func TestUnusableSkipped(t *testing.T) {
	c, _ := danetest.NewSelfSigned(t, danetest.CertOpts{})
	res, err := Verify([]*x509.Certificate{c}, rrs(TLSA{3, 1, 9, []byte{1}}), VerifyOptions{})
	if err == nil || res.Records[0].Status != StatusSkipped || !strings.Contains(res.Records[0].Detail, "unusable") {
		t.Fatalf("res=%+v err=%v", res, err)
	}
}

func TestEmptyChain(t *testing.T) {
	for _, ch := range [][]*x509.Certificate{nil, {nil}} {
		if _, err := Verify(ch, rrs(), VerifyOptions{}); !errors.Is(err, ErrNoChain) {
			t.Fatalf("err=%v", err)
		}
	}
}

func TestNilOrEmptyRRset(t *testing.T) {
	c, _ := danetest.NewSelfSigned(t, danetest.CertOpts{})
	for _, r := range []*RRset{nil, rrs()} {
		res, err := Verify([]*x509.Certificate{c}, r, VerifyOptions{})
		if !errors.Is(err, ErrNotAuthenticated) || res == nil || res.Authenticated {
			t.Fatalf("res=%+v err=%v", res, err)
		}
	}
}

func TestRecordStatusString(t *testing.T) {
	if StatusMatched.String() != "matched" || StatusSkipped.String() != "skipped" ||
		StatusNoMatch.String() != "nomatch" || StatusFailed.String() != "failed" {
		t.Fatal("bad String")
	}
}

func chainOf(cs ...*x509.Certificate) []*x509.Certificate { return cs }

func poolOf(cs ...*x509.Certificate) *x509.CertPool {
	p := x509.NewCertPool()
	for _, c := range cs {
		p.AddCert(c)
	}
	return p
}

func TestDANETAMatch(t *testing.T) {
	ca, key := danetest.NewCA(t, "ca")
	leaf, _ := danetest.NewLeaf(t, ca, key, danetest.CertOpts{DNSNames: []string{"dev1.example.com"}})
	res, err := Verify(chainOf(leaf, ca), rrs(mustTLSA(t, DANETA, SelectorCert, MatchSHA256, ca)),
		VerifyOptions{Role: RoleClient, Name: "dev1.example.com"})
	if err != nil || !res.Authenticated || res.Matched.Depth != 1 {
		t.Fatalf("res=%+v err=%v", res, err)
	}
}

func TestDANETASPKI(t *testing.T) {
	ca, key := danetest.NewCA(t, "ca")
	leaf, _ := danetest.NewLeaf(t, ca, key, danetest.CertOpts{DNSNames: []string{"dev1.example.com"}})
	res, err := Verify(chainOf(leaf, ca), rrs(mustTLSA(t, DANETA, SelectorSPKI, MatchSHA256, ca)),
		VerifyOptions{Role: RoleClient, Name: "dev1.example.com"})
	if err != nil || !res.Authenticated {
		t.Fatalf("res=%+v err=%v", res, err)
	}
}

func TestDANETANameMismatch(t *testing.T) {
	ca, key := danetest.NewCA(t, "ca")
	leaf, _ := danetest.NewLeaf(t, ca, key, danetest.CertOpts{DNSNames: []string{"dev1.example.com"}})
	res, err := Verify(chainOf(leaf, ca), rrs(mustTLSA(t, DANETA, SelectorCert, MatchSHA256, ca)),
		VerifyOptions{Role: RoleClient, Name: "other.example.com"})
	if !errors.Is(err, ErrNameMismatch) || !errors.Is(err, ErrNotAuthenticated) || res.Authenticated {
		t.Fatalf("res=%+v err=%v", res, err)
	}
	if res.Records[0].Status != StatusFailed {
		t.Fatalf("status=%v", res.Records[0].Status)
	}
}

func TestDANETATANotInChain200(t *testing.T) {
	ca, key := danetest.NewCA(t, "ca")
	leaf, _ := danetest.NewLeaf(t, ca, key, danetest.CertOpts{DNSNames: []string{"dev1.example.com"}})
	res, err := Verify(chainOf(leaf), rrs(mustTLSA(t, DANETA, SelectorCert, MatchFull, ca)),
		VerifyOptions{Role: RoleClient, Name: "dev1.example.com"})
	if err != nil || !res.Authenticated || res.Matched.Depth != 1 {
		t.Fatalf("res=%+v err=%v", res, err)
	}
}

func TestDANETATANotInChainDigest(t *testing.T) {
	ca, key := danetest.NewCA(t, "ca")
	leaf, _ := danetest.NewLeaf(t, ca, key, danetest.CertOpts{DNSNames: []string{"dev1.example.com"}})
	res, err := Verify(chainOf(leaf), rrs(mustTLSA(t, DANETA, SelectorCert, MatchSHA256, ca)),
		VerifyOptions{Role: RoleClient, Name: "dev1.example.com"})
	if err == nil || res.Authenticated || res.Records[0].Status != StatusNoMatch {
		t.Fatalf("res=%+v err=%v", res, err)
	}
}

func TestDANETAExtraCert(t *testing.T) {
	ca, key := danetest.NewCA(t, "ca")
	other, _ := danetest.NewCA(t, "other")
	leaf, _ := danetest.NewLeaf(t, ca, key, danetest.CertOpts{DNSNames: []string{"dev1.example.com"}})
	res, err := Verify(chainOf(leaf, other, ca), rrs(mustTLSA(t, DANETA, SelectorCert, MatchSHA256, ca)),
		VerifyOptions{Role: RoleClient, Name: "dev1.example.com"})
	if err != nil || !res.Authenticated || res.Matched.Depth != 2 {
		t.Fatalf("res=%+v err=%v", res, err)
	}
}

func TestDANETAWrongIssuer(t *testing.T) {
	caA, keyA := danetest.NewCA(t, "caA")
	caB, _ := danetest.NewCA(t, "caB")
	leaf, _ := danetest.NewLeaf(t, caA, keyA, danetest.CertOpts{DNSNames: []string{"dev1.example.com"}})
	res, err := Verify(chainOf(leaf, caB), rrs(mustTLSA(t, DANETA, SelectorCert, MatchSHA256, caB)),
		VerifyOptions{Role: RoleClient, Name: "dev1.example.com"})
	if err == nil || res.Authenticated || res.Records[0].Status != StatusFailed {
		t.Fatalf("res=%+v err=%v", res, err)
	}
}

func TestDANETAClientEKU(t *testing.T) {
	ca, key := danetest.NewCA(t, "ca")
	cases := []struct {
		name string
		eku  []x509.ExtKeyUsage
		ok   bool
	}{
		{"server only", []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, false},
		{"none", nil, true},
		{"client", []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			leaf, _ := danetest.NewLeaf(t, ca, key, danetest.CertOpts{DNSNames: []string{"dev1.example.com"}, ExtKeyUsage: c.eku})
			res, _ := Verify(chainOf(leaf, ca), rrs(mustTLSA(t, DANETA, SelectorCert, MatchSHA256, ca)),
				VerifyOptions{Role: RoleClient, Name: "dev1.example.com"})
			if res.Authenticated != c.ok {
				t.Fatalf("got %v want %v: %+v", res.Authenticated, c.ok, res.Records[0])
			}
			if !c.ok && res.Records[0].Status != StatusFailed {
				t.Fatalf("status=%v", res.Records[0].Status)
			}
		})
	}
}

func TestDANETAExpiredLeaf(t *testing.T) {
	ca, key := danetest.NewCA(t, "ca")
	leaf, _ := danetest.NewLeaf(t, ca, key, danetest.CertOpts{
		DNSNames:  []string{"dev1.example.com"},
		NotBefore: time.Now().Add(-48 * time.Hour),
		NotAfter:  time.Now().Add(-24 * time.Hour),
	})
	res, err := Verify(chainOf(leaf, ca), rrs(mustTLSA(t, DANETA, SelectorCert, MatchSHA256, ca)),
		VerifyOptions{Role: RoleClient, Name: "dev1.example.com"})
	if err == nil || res.Authenticated || res.Records[0].Status != StatusFailed {
		t.Fatalf("res=%+v err=%v", res, err)
	}
}

func TestClientNameCheckCaseAndDot(t *testing.T) {
	ca, key := danetest.NewCA(t, "ca")
	leaf, _ := danetest.NewLeaf(t, ca, key, danetest.CertOpts{DNSNames: []string{"dev1.example.com"}})
	res, err := Verify(chainOf(leaf, ca), rrs(mustTLSA(t, DANETA, SelectorCert, MatchSHA256, ca)),
		VerifyOptions{Role: RoleClient, Name: "DEV1.Example.COM."})
	if err != nil || !res.Authenticated {
		t.Fatalf("res=%+v err=%v", res, err)
	}
}

// Documents that the library does not reject underscore labels.
func TestClientNameUnderscore(t *testing.T) {
	ca, key := danetest.NewCA(t, "ca")
	leaf, _ := danetest.NewLeaf(t, ca, key, danetest.CertOpts{DNSNames: []string{"_smtp._client.mta1.example.com"}})
	res, err := Verify(chainOf(leaf, ca), rrs(mustTLSA(t, DANETA, SelectorCert, MatchSHA256, ca)),
		VerifyOptions{Role: RoleClient, Name: "_SMTP._client.MTA1.example.com."})
	if err != nil || !res.Authenticated {
		t.Fatalf("res=%+v err=%v", res, err)
	}
}

func TestPKIXEE(t *testing.T) {
	ca, key := danetest.NewCA(t, "ca")
	leaf, _ := danetest.NewLeaf(t, ca, key, danetest.CertOpts{DNSNames: []string{"www.example.com"}})
	rr := rrs(mustTLSA(t, PKIXEE, SelectorSPKI, MatchSHA256, leaf))
	res, err := Verify(chainOf(leaf), rr, VerifyOptions{Role: RoleServer, Name: "www.example.com", Roots: poolOf(ca)})
	if err != nil || !res.Authenticated || res.Matched.Depth != 0 {
		t.Fatalf("res=%+v err=%v", res, err)
	}
	other, _ := danetest.NewCA(t, "other")
	res, err = Verify(chainOf(leaf), rr, VerifyOptions{Role: RoleServer, Name: "www.example.com", Roots: poolOf(other)})
	if err == nil || res.Authenticated || res.Records[0].Status != StatusFailed {
		t.Fatalf("res=%+v err=%v", res, err)
	}
}

func TestPKIXTA(t *testing.T) {
	ca, key := danetest.NewCA(t, "ca")
	leaf, _ := danetest.NewLeaf(t, ca, key, danetest.CertOpts{DNSNames: []string{"www.example.com"}})
	res, err := Verify(chainOf(leaf), rrs(mustTLSA(t, PKIXTA, SelectorCert, MatchSHA256, ca)),
		VerifyOptions{Role: RoleServer, Name: "www.example.com", Roots: poolOf(ca)})
	if err != nil || !res.Authenticated || res.Matched.Depth != 1 {
		t.Fatalf("res=%+v err=%v", res, err)
	}
}

func TestServerNameWildcard(t *testing.T) {
	ca, key := danetest.NewCA(t, "ca")
	leaf, _ := danetest.NewLeaf(t, ca, key, danetest.CertOpts{DNSNames: []string{"*.example.com"}})
	res, err := Verify(chainOf(leaf, ca), rrs(mustTLSA(t, DANETA, SelectorCert, MatchSHA256, ca)),
		VerifyOptions{Role: RoleServer, Name: "www.example.com"})
	if err != nil || !res.Authenticated {
		t.Fatalf("res=%+v err=%v", res, err)
	}
}

func TestPKIXTANegative(t *testing.T) {
	ca, key := danetest.NewCA(t, "ca")
	other, _ := danetest.NewCA(t, "other")
	leaf, _ := danetest.NewLeaf(t, ca, key, danetest.CertOpts{DNSNames: []string{"www.example.com"}})
	res, err := Verify(chainOf(leaf), rrs(mustTLSA(t, PKIXTA, SelectorCert, MatchSHA256, other)),
		VerifyOptions{Role: RoleServer, Name: "www.example.com", Roots: poolOf(ca)})
	if !errors.Is(err, ErrNotAuthenticated) || res.Authenticated || res.Records[0].Status != StatusNoMatch {
		t.Fatalf("res=%+v err=%v", res, err)
	}
}

func TestDANETA200SelfSignedEE(t *testing.T) {
	ee, _ := danetest.NewSelfSigned(t, danetest.CertOpts{DNSNames: []string{"dev1.example.com"}})
	res, err := Verify(chainOf(ee), rrs(mustTLSA(t, DANETA, SelectorCert, MatchFull, ee)),
		VerifyOptions{Role: RoleClient, Name: "dev1.example.com"})
	if err != nil || !res.Authenticated {
		t.Fatalf("res=%+v err=%v", res, err)
	}
}

func clientNameCase(t *testing.T, san, name string) (*Result, error) {
	t.Helper()
	ca, key := danetest.NewCA(t, "ca")
	leaf, _ := danetest.NewLeaf(t, ca, key, danetest.CertOpts{DNSNames: []string{san}})
	return Verify(chainOf(leaf, ca), rrs(mustTLSA(t, DANETA, SelectorCert, MatchSHA256, ca)),
		VerifyOptions{Role: RoleClient, Name: name})
}

func TestClientNameNoWildcardMatch(t *testing.T) {
	res, err := clientNameCase(t, "*.example.com", "www.example.com")
	if res.Authenticated || !errors.Is(err, ErrNameMismatch) || res.Records[0].Status != StatusFailed {
		t.Fatalf("res=%+v err=%v", res, err)
	}
}

func TestClientNameLiteralWildcardRejected(t *testing.T) {
	res, err := clientNameCase(t, "*.example.com", "*.example.com")
	if res.Authenticated || !errors.Is(err, ErrNameMismatch) {
		t.Fatalf("res=%+v err=%v", res, err)
	}
}

func TestClientNameNonASCIIFold(t *testing.T) {
	res, err := clientNameCase(t, "key.example.com", "\u212aey.example.com")
	if res.Authenticated || !errors.Is(err, ErrNameMismatch) {
		t.Fatalf("res=%+v err=%v", res, err)
	}
}

func TestClientNameEmptyLabel(t *testing.T) {
	res, err := clientNameCase(t, "a..example.com", "a..example.com")
	if res.Authenticated || !errors.Is(err, ErrNameMismatch) {
		t.Fatalf("res=%+v err=%v", res, err)
	}
}
