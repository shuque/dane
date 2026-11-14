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
