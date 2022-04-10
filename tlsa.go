package dane

import (
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"fmt"
)

//
// DANE Certificte Usage modes
//
const (
	PkixTA = 0 // Certificate Authority Constraint
	PkixEE = 1 // Service Certificate Constraint
	DaneTA = 2 // Trust Anchor Assertion
	DaneEE = 3 // Domain Issued Certificate
)

//
// TLSArdata - TLSA rdata structure
//
type TLSArdata struct {
	Usage    uint8  // Certificate Usage
	Selector uint8  // Selector: 0: full cert, 1: subject public key
	Mtype    uint8  // Matching Type: 0: full content, 1: SHA256, 2: SHA512
	Data     string // Certificate association Data field (hex encoding)
	Checked  bool   // Have we tried to match this TLSA rdata?
	Ok       bool   // Did it match?
	Message  string // Diagnostic message for matching
}

//
// String returns a string representation of the TLSA rdata.
//
func (tr *TLSArdata) String() string {
	return fmt.Sprintf("DANE TLSA %d %d %d [%s..]",
		tr.Usage, tr.Selector, tr.Mtype, tr.Data[0:8])
}

//
// TLSAinfo contains details of the TLSA RRset.
//
type TLSAinfo struct {
	Qname string
	Alias []string
	Rdata []*TLSArdata
}

//
// Copy makes a deep copy of the TLSAinfo structure
//
func (t *TLSAinfo) Copy() *TLSAinfo {
	c := new(TLSAinfo)
	c.Qname = t.Qname
	c.Alias = append(c.Alias, t.Alias...)
	for _, r := range t.Rdata {
		tr := new(TLSArdata)
		tr.Usage = r.Usage
		tr.Selector = r.Selector
		tr.Mtype = r.Mtype
		tr.Data = r.Data
		c.Rdata = append(c.Rdata, tr)
	}
	return c
}

//
// Uncheck unchecks result fields of all the TLSA rdata structs.
//
func (t *TLSAinfo) Uncheck() {
	for _, tr := range t.Rdata {
		tr.Checked = false
		tr.Ok = false
		tr.Message = ""
	}
}

//
// Results prints TLSA RRset certificate matching results.
//
func (t *TLSAinfo) Results() {
	if t.Rdata == nil {
		fmt.Printf("No TLSA records available.\n")
		return
	}
	for _, tr := range t.Rdata {
		if !tr.Checked {
			fmt.Printf("%s: not checked\n", tr)
		} else if tr.Ok {
			fmt.Printf("%s: OK %s\n", tr, tr.Message)
		} else {
			fmt.Printf("%s: FAIL %s\n", tr, tr.Message)
		}
	}
}

//
// Print prints information about the TLSAinfo TLSA RRset.
func (t *TLSAinfo) Print() {
	fmt.Printf("DNS TLSA RRset:\n  qname: %s\n", t.Qname)
	if t.Alias != nil {
		fmt.Printf("  alias: %s\n", t.Alias)
	}
	for _, tr := range t.Rdata {
		fmt.Printf("  %d %d %d %s\n", tr.Usage, tr.Selector, tr.Mtype, tr.Data)
	}
}

//
// ComputeTLSA calculates the TLSA rdata hash value for the given certificate
// from the given DANE selector and matching type. Returns the hex encoded
// string form of the value, and sets error to non-nil on failure.
//
func ComputeTLSA(selector, mtype uint8, cert *x509.Certificate) (string, error) {

	var preimage asn1.RawContent
	var output []byte
	var tmp256 [32]byte
	var tmp512 [64]byte

	switch selector {
	case 0:
		preimage = cert.Raw
	case 1:
		preimage = cert.RawSubjectPublicKeyInfo
	default:
		return "", fmt.Errorf("unknown TLSA selector: %d", selector)
	}

	switch mtype {
	case 0:
		output = preimage
	case 1:
		tmp256 = sha256.Sum256(preimage)
		output = tmp256[:]
	case 2:
		tmp512 = sha512.Sum512(preimage)
		output = tmp512[:]
	default:
		return "", fmt.Errorf("unknown TLSA matching type: %d", mtype)
	}
	return hex.EncodeToString(output), nil
}

//
// ChainMatchesTLSA checks that the TLSA record data (tr) has a corresponding
// match in the certificate chain (chain). Only one TLSA record needs to match
// for the chain to be considered matched. However, this function checks all
// available TLSA records and records the results of the match in the TLSArdata
// structure. These results can be useful to diagnostic tools using this
// package.
//
func ChainMatchesTLSA(chain []*x509.Certificate, tr *TLSArdata, daneconfig *Config) bool {

	var Authenticated = false
	var hash string
	var err error
	var hashMatched bool

	tr.Checked = true
	switch tr.Usage {
	case PkixEE, DaneEE:
		hash, err = ComputeTLSA(tr.Selector, tr.Mtype, chain[0])
		if err != nil {
			tr.Ok = false
			tr.Message = err.Error()
			break
		}
		if hash == tr.Data {
			if tr.Usage == DaneEE || daneconfig.Okpkix {
				Authenticated = true
				tr.Ok = true
				tr.Message = "matched EE certificate"
			} else {
				tr.Ok = false
				tr.Message = "matched EE certificate but PKIX failed"
			}
		} else {
			tr.Ok = false
			tr.Message = "did not match EE certificate"
		}
	case PkixTA, DaneTA:
		for i, cert := range chain[1:] {
			hash, err = ComputeTLSA(tr.Selector, tr.Mtype, cert)
			if err != nil {
				tr.Ok = false
				tr.Message = err.Error()
				break
			}
			if hash != tr.Data {
				continue
			}
			hashMatched = true
			if tr.Usage == DaneTA || daneconfig.Okpkix {
				Authenticated = true
				tr.Ok = true
				tr.Message = fmt.Sprintf("matched TA certificate at depth %d", i+1)
			} else {
				tr.Ok = false
				tr.Message = fmt.Sprintf("matched TA certificate at depth %d but PKIX failed", i+1)
			}
		}
		if !hashMatched {
			tr.Ok = false
			tr.Message = "did not match any TA certificate"
		}
	default:
		tr.Ok = false
		tr.Message = fmt.Sprintf("invalid usage mode: %d", tr.Usage)
	}

	return Authenticated
}

//
// smtpUsageOK returns whether the TLSA rdata set is valid for SMTP
// STARTTLS. By default, per spec, only DANE usage modes 2 and 3 are
// permitted. But if the SMTPAnyMode flag is set, all modes are allowed
// and the function unconditionally returns true.
//
func smtpUsageOK(tr *TLSArdata, daneconfig *Config) bool {

	if daneconfig.SMTPAnyMode {
		return true
	}

	if tr.Usage == 2 || tr.Usage == 3 {
		return true
	}

	return false
}

//
// AuthenticateSingle performs DANE authentication of a single certificate
// chain, using a single TLSA resource data. Returns true or false accordingly.
//
func AuthenticateSingle(chain []*x509.Certificate, tr *TLSArdata, daneconfig *Config) bool {

	var err error

	tr.Checked = true

	if daneconfig.Appname == "smtp" && !smtpUsageOK(tr, daneconfig) {
		tr.Ok = false
		tr.Message = "invalid usage mode for smtp"
		return false
	}

	if !ChainMatchesTLSA(chain, tr, daneconfig) {
		return false
	}

	if tr.Usage == DaneEE && !daneconfig.DaneEEname {
		return true
	}

	err = chain[0].VerifyHostname(daneconfig.Server.Name)
	if err == nil {
		return true
	} else {
		tr.Ok = false
		tr.Message += " but name check failed"
		return false
	}
}

//
// AuthenticateAll performs DANE authentication of a set of certificate chains.
// The TLSA RRset information is expected to be pre-initialized in the dane
// Config structure.
//
func AuthenticateAll(daneconfig *Config) {

	var chains [][]*x509.Certificate

	daneconfig.Okdane = false

	for _, tr := range daneconfig.TLSA.Rdata {
		switch tr.Usage {
		case DaneEE, DaneTA:
			chains = daneconfig.DANEChains
		case PkixEE, PkixTA:
			chains = daneconfig.PKIXChains
		}
		for _, chain := range chains {
			if AuthenticateSingle(chain, tr, daneconfig) {
				daneconfig.Okdane = true
			}
		}
	}
}
