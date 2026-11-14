package dane

import (
	"bytes"
	"crypto/sha256"
	"crypto/sha512"
	"testing"

	"github.com/shuque/dane/v2/danetest"
)

func TestComputeData(t *testing.T) {
	c, _ := danetest.NewSelfSigned(t, danetest.CertOpts{DNSNames: []string{"example.com"}})

	got, err := ComputeData(SelectorCert, MatchFull, c)
	if err != nil || !bytes.Equal(got, c.Raw) {
		t.Errorf("cert/full mismatch: err=%v", err)
	}
	h256 := sha256.Sum256(c.RawSubjectPublicKeyInfo)
	got, err = ComputeData(SelectorSPKI, MatchSHA256, c)
	if err != nil || !bytes.Equal(got, h256[:]) {
		t.Errorf("spki/sha256 mismatch: err=%v", err)
	}
	h512 := sha512.Sum512(c.RawSubjectPublicKeyInfo)
	got, err = ComputeData(SelectorSPKI, MatchSHA512, c)
	if err != nil || !bytes.Equal(got, h512[:]) {
		t.Errorf("spki/sha512 mismatch: err=%v", err)
	}
	if _, err := ComputeData(Selector(2), MatchFull, c); err == nil {
		t.Error("selector 2: expected error")
	}
	if _, err := ComputeData(SelectorCert, MatchingType(3), c); err == nil {
		t.Error("matching type 3: expected error")
	}
}

func TestNewTLSA(t *testing.T) {
	c, _ := danetest.NewSelfSigned(t, danetest.CertOpts{})
	tl, err := NewTLSA(DANEEE, SelectorSPKI, MatchSHA256, c)
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256(c.RawSubjectPublicKeyInfo)
	if tl.Usage != DANEEE || !bytes.Equal(tl.Data, h[:]) || !tl.Usable() {
		t.Errorf("unexpected %v", tl)
	}
}

func TestTLSAStringParseRoundTrip(t *testing.T) {
	got, err := ParseTLSA("3 1 1 AB cd")
	if err != nil {
		t.Fatal(err)
	}
	want := TLSA{3, 1, 1, []byte{0xab, 0xcd}}
	if got.Usage != want.Usage || got.Selector != want.Selector ||
		got.MatchingType != want.MatchingType || !bytes.Equal(got.Data, want.Data) {
		t.Errorf("got %+v", got)
	}
	if s := got.String(); s != "3 1 1 abcd" {
		t.Errorf("String() = %q", s)
	}
	for _, bad := range []string{"3 1", "3 1 1 zz"} {
		if _, err := ParseTLSA(bad); err == nil {
			t.Errorf("ParseTLSA(%q): expected error", bad)
		}
	}
}

func TestUsable(t *testing.T) {
	x := []byte{1}
	for _, tl := range []TLSA{{4, 1, 1, x}, {3, 2, 1, x}, {3, 1, 3, x}, {3, 1, 1, nil}} {
		if tl.Usable() {
			t.Errorf("%v should not be usable", tl)
		}
	}
	if !(TLSA{2, 0, 0, x}).Usable() {
		t.Error("2 0 0 should be usable")
	}
}
