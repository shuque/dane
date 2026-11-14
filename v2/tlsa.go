package dane

import (
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
)

// Usage is the TLSA certificate usage field.
type Usage uint8

// Selector is the TLSA selector field.
type Selector uint8

// MatchingType is the TLSA matching type field.
type MatchingType uint8

const (
	PKIXTA Usage = 0
	PKIXEE Usage = 1
	DANETA Usage = 2
	DANEEE Usage = 3
)

const (
	SelectorCert Selector = 0
	SelectorSPKI Selector = 1
)

const (
	MatchFull   MatchingType = 0
	MatchSHA256 MatchingType = 1
	MatchSHA512 MatchingType = 2
)

// TLSA is a TLSA record's RDATA.
type TLSA struct {
	Usage        Usage
	Selector     Selector
	MatchingType MatchingType
	Data         []byte // raw association data (not hex)
}

// String returns "usage selector mtype hex" with lowercase hex.
func (t TLSA) String() string {
	return fmt.Sprintf("%d %d %d %s", t.Usage, t.Selector, t.MatchingType, hex.EncodeToString(t.Data))
}

// Usable reports whether the record has defined field values and data.
func (t TLSA) Usable() bool {
	return t.Usage <= 3 && t.Selector <= 1 && t.MatchingType <= 2 && len(t.Data) > 0
}

// ParseTLSA parses the format produced by String. Whitespace within the
// hex data is allowed.
func ParseTLSA(s string) (TLSA, error) {
	f := strings.Fields(s)
	if len(f) < 4 {
		return TLSA{}, fmt.Errorf("dane: TLSA %q: need usage, selector, matching type and data", s)
	}
	var v [3]uint8
	for i := 0; i < 3; i++ {
		n, err := strconv.ParseUint(f[i], 10, 8)
		if err != nil {
			return TLSA{}, fmt.Errorf("dane: TLSA %q: bad field %q", s, f[i])
		}
		v[i] = uint8(n)
	}
	d, err := hex.DecodeString(strings.Join(f[3:], ""))
	if err != nil {
		return TLSA{}, fmt.Errorf("dane: TLSA %q: bad hex data: %w", s, err)
	}
	return TLSA{Usage(v[0]), Selector(v[1]), MatchingType(v[2]), d}, nil
}

// ComputeData returns the TLSA association data for cert under the given
// selector and matching type.
func ComputeData(sel Selector, mt MatchingType, cert *x509.Certificate) ([]byte, error) {
	var b []byte
	switch sel {
	case SelectorCert:
		b = cert.Raw
	case SelectorSPKI:
		b = cert.RawSubjectPublicKeyInfo
	default:
		return nil, fmt.Errorf("dane: unsupported selector %d", sel)
	}
	switch mt {
	case MatchFull:
		return append([]byte(nil), b...), nil
	case MatchSHA256:
		h := sha256.Sum256(b)
		return h[:], nil
	case MatchSHA512:
		h := sha512.Sum512(b)
		return h[:], nil
	}
	return nil, fmt.Errorf("dane: unsupported matching type %d", mt)
}

// NewTLSA builds a TLSA record matching cert.
func NewTLSA(u Usage, sel Selector, mt MatchingType, cert *x509.Certificate) (TLSA, error) {
	d, err := ComputeData(sel, mt, cert)
	if err != nil {
		return TLSA{}, err
	}
	return TLSA{u, sel, mt, d}, nil
}
