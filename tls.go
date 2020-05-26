package dane

import (
	"crypto/sha256"
	"crypto/sha512"
	"crypto/tls"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"fmt"
	"net"
)

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
		return "", fmt.Errorf("Unknown TLSA selector: %d", selector)
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
		return "", fmt.Errorf("Unknown TLSA matching type: %d", mtype)
	}
	return hex.EncodeToString(output), nil
}

//
// ChainMatchesTLSA checks that the TLSA record data (tr) has a corresponding
// match in the certificate chain (chain). It checks _all_ available TLSA
// records against the chain, and records the status in TLSArdata structure.
//
func ChainMatchesTLSA(chain []*x509.Certificate, tr *TLSArdata, daneconfig *Config) bool {

	var Authenticated = false
	var hash string
	var err error
	var hashMatched bool

	tr.checked = true
	switch tr.usage {
	case 1, 3:
		hash, err = ComputeTLSA(tr.selector, tr.mtype, chain[0])
		if err != nil {
			tr.ok = false
			tr.message = err.Error()
			break
		}
		if hash == tr.data {
			if tr.usage == 3 || daneconfig.Okpkix {
				Authenticated = true
				tr.ok = true
				tr.message = "matched EE certificate"
			} else {
				tr.ok = false
				tr.message = "matched EE certificate but PKIX failed"
			}
		} else {
			tr.ok = false
			tr.message = "did not match EE certificate"
		}
	case 0, 2:
		for i, cert := range chain[1:] {
			hash, err = ComputeTLSA(tr.selector, tr.mtype, cert)
			if err != nil {
				tr.ok = false
				tr.message = err.Error()
				break
			}
			if hash != tr.data {
				continue
			}
			hashMatched = true
			if tr.usage == 2 || daneconfig.Okpkix {
				Authenticated = true
				tr.ok = true
				tr.message = fmt.Sprintf("matched TA certificate at depth %d", i+1)
			} else {
				tr.ok = false
				tr.message = fmt.Sprintf("matched TA certificate at depth %d but PKIX failed", i+1)
			}
		}
		if !hashMatched {
			tr.ok = false
			tr.message = "did not match any TA certificate"
		}
	default:
		tr.ok = false
		tr.message = fmt.Sprintf("invalid usage mode: %d", tr.usage)
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

	if tr.usage == 2 || tr.usage == 3 {
		return true
	}

	return false
}

//
// AuthenticateSingle performs DANE authentication of a single certificate
// chain, using the TLSA RRset information embedded in the provided dane
// Config. Returns true or false accordingly. It checks _all_ available
// TLSA records against the certificate chain, and records the status in
// TLSAinfo structure inside Config.
//
func AuthenticateSingle(chain []*x509.Certificate, daneconfig *Config) bool {

	var Authenticated, ok bool
	var err error

	for _, tr := range daneconfig.TLSA.rdata {
		tr.checked = true
		if daneconfig.Appname == "smtp" && !smtpUsageOK(tr, daneconfig) {
			tr.ok = false
			tr.message = "invalid usage mode for smtp"
			continue
		}
		ok = ChainMatchesTLSA(chain, tr, daneconfig)
		if !ok {
			continue
		}
		if tr.usage == 3 && !daneconfig.DaneEEname {
			Authenticated = true
			continue
		}
		err = chain[0].VerifyHostname(daneconfig.Server.Name)
		if err == nil {
			Authenticated = true
		} else {
			tr.ok = false
			tr.message += " but name check failed"
		}
	}

	return Authenticated
}

//
// AuthenticateAll performs DANE authentication of a set of certificate chains.
// The TLSA RRset information is expected to be pre-initialized in the dane
// Config structure. If there are multiple chains, usually one is a superset of
// another. So it just returns true, once a single chain authenticates. Returns
// false if no chain authenticates.
//
func AuthenticateAll(daneconfig *Config) bool {

	var ok bool

	for _, chain := range daneconfig.Certchains {
		ok = AuthenticateSingle(chain, daneconfig)
		if ok {
			return true
		}
	}
	return false
}

//
// verifyChain performs certificate chain validation of the given chain (list)
// of certificates. On success it returns a list of verified chains. On failure,
// it sets error to non-nil with an embedded error string. If "root" is true,
// then the system's root certificate store is used to find a trust anchor.
// Otherwise, it sets the tail certificate of the chain as the root trust
// anchor (self signed mode).
//
func verifyChain(certs []*x509.Certificate, config *tls.Config,
	root bool) ([][]*x509.Certificate, error) {

	var verifiedChains [][]*x509.Certificate
	var err error
	var opts x509.VerifyOptions

	if root {
		opts.Roots = config.RootCAs
		opts.Intermediates = x509.NewCertPool()

		for _, cert := range certs[1:] {
			opts.Intermediates.AddCert(cert)
		}
		verifiedChains, err = certs[0].Verify(opts)
	} else {
		opts.Roots = x509.NewCertPool()

		chainlength := len(certs)
		last := certs[chainlength-1]
		opts.Roots.AddCert(last)
		if chainlength >= 3 {
			opts.Intermediates = x509.NewCertPool()
			for _, cert := range certs[1:] {
				opts.Intermediates.AddCert(cert)
			}
		}
		verifiedChains, err = certs[0].Verify(opts)
	}
	return verifiedChains, err
}

//
// verifyServer is a custom callback function configure in the tls
// Config data structure that performs DANE and PKIX authentication of
// the server certificate as appropriate.
//
func verifyServer(rawCerts [][]byte,
	verifiedChains [][]*x509.Certificate,
	tlsconfig *tls.Config, daneconfig *Config) error {

	var err error
	certs := make([]*x509.Certificate, len(rawCerts))

	for i, asn1Data := range rawCerts {
		cert, err := x509.ParseCertificate(asn1Data)
		if err != nil {
			return fmt.Errorf("failed to parse server certificate: %s", err.Error())
		}
		certs[i] = cert
	}

	daneconfig.Certchains, err = verifyChain(certs, tlsconfig, true)
	if err == nil {
		daneconfig.Okpkix = true
	}

	if !(daneconfig.DANE && daneconfig.TLSA != nil) {
		if !daneconfig.Okpkix {
			return err
		}
		return certs[0].VerifyHostname(tlsconfig.ServerName)
	}

	if !daneconfig.Okpkix {
		daneconfig.Certchains, err = verifyChain(certs, tlsconfig, false)
		if err != nil {
			return fmt.Errorf("DANE TLS error: cert chain: %s", err.Error())
		}
	}

	// TODO: set Okdane inside AuthenticateAll and return no value?
	daneconfig.Okdane = AuthenticateAll(daneconfig)
	if !daneconfig.Okdane {
		return fmt.Errorf("DANE TLS authentication failed")
	}

	return nil
}

//
// GetTLSconfig takes a dane Config structure, and returns a tls Config
// initialized with the ServerName, and a custom server certificate
// verification callback that performs DANE authentication.
//
func GetTLSconfig(daneconfig *Config) *tls.Config {

	config := new(tls.Config)
	config.ServerName = daneconfig.Server.Name
	config.InsecureSkipVerify = true
	config.VerifyPeerCertificate = func(rawCerts [][]byte,
		verifiedChains [][]*x509.Certificate) error {
		return verifyServer(rawCerts, verifiedChains, config, daneconfig)
	}
	return config
}

//
// TLShandshake takes a network connection and a TLS Config structure,
// negotatiates TLS on the connection and returns a TLS connection on
// success. It sets error to non-nil on failure.
//
func TLShandshake(conn net.Conn, config *tls.Config) (*tls.Conn, error) {

	tlsconn := tls.Client(conn, config)
	err := tlsconn.Handshake()
	return tlsconn, err
}

//
// DialTLS takes a pointer to an initialized dane Config structure,
// establishes and returns a TLS connection. The error return parameter
// is nil on success, and appropriately populated if not.
//
// DialTLS obtains a TLS config structure initialized with Dane
// verification callbacks, and connects to the server network address
// defined in Config using tls.DialWithDialer().
//
func DialTLS(daneconfig *Config) (*tls.Conn, error) {

	var err error
	var conn *tls.Conn

	server := daneconfig.Server

	config := GetTLSconfig(daneconfig)
	dialer := getDialer(defaultTCPTimeout)
	conn, err = tls.DialWithDialer(dialer, "tcp", server.Address(), config)
	return conn, err
}

//
// DialStartTLS takes a pointer to an initialized dane Config structure,
// connects to the defined server, speaks the necessary application
// protocol preamble to activate STARTTLS, then negotiates TLS and returns
// the TLS connection. The error return parameter is nil on success, and
// appropriately populated if not.
//
// DialStartTLS obtains a TLS config structure, initialized with Dane
// verification callbacks, and connects to the server network address
// defined in Config using tls.DialWithDialer().
//
func DialStartTLS(daneconfig *Config) (*tls.Conn, error) {

	var err error
	var conn *tls.Conn

	server := daneconfig.Server

	config := GetTLSconfig(daneconfig)
	conn, err = StartTLS(server, config, daneconfig)
	return conn, err
}
