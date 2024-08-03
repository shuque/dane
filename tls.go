package dane

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
)

// verifyChain performs certificate chain validation of the given chain (list)
// of certificates. On success it returns a list of verified chains. On failure,
// it sets error to non-nil with an embedded error string. If "root" is true,
// then the system's root certificate store is used to find a trust anchor.
// Otherwise, it sets the tail certificate of the chain as the root trust
// anchor (self signed mode).
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

// verifyServer is a custom callback function configure in the tls
// Config data structure that performs DANE and PKIX authentication of
// the server certificate as appropriate.
func verifyServer(rawCerts [][]byte,
	_ [][]*x509.Certificate,
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

	daneconfig.PeerChain = certs
	daneconfig.PKIXChains, err = verifyChain(certs, tlsconfig, true)
	if err == nil {
		daneconfig.Okpkix = true
	}

	if !(daneconfig.DANE && daneconfig.TLSA != nil) {
		if !daneconfig.Okpkix {
			if daneconfig.DiagMode {
				daneconfig.DiagError = err
				return nil
			}
			return err
		}
		err = certs[0].VerifyHostname(tlsconfig.ServerName)
		if daneconfig.DiagMode {
			daneconfig.DiagError = err
			return nil
		}
		return err
	}

	// Now we have to do DANE verification. Run verifyChain() with root=false
	// and assign the chain to DANEChains.

	daneChains, err := verifyChain(certs, tlsconfig, false)
	if err != nil {
		if daneconfig.PKIX && daneconfig.Okpkix {
			daneconfig.DiagError = fmt.Errorf("DANE TLS error: cert chain: %s", err.Error())
			if daneconfig.DiagMode {
				return nil
			} else {
				return daneconfig.DiagError
			}
		}
	}
	daneconfig.DANEChains = daneChains

	AuthenticateAll(daneconfig)
	if !daneconfig.Okdane {
		daneconfig.DiagError = fmt.Errorf("DANE TLS authentication failed")
		if daneconfig.DiagMode {
			return nil
		} else {
			return daneconfig.DiagError
		}
	}

	return nil
}

// GetTLSconfig takes a dane Config structure, and returns a tls Config
// initialized with the ServerName, other specified TLS parameters, and a
// custom server certificate verification callback that performs DANE
// authentication.
func GetTLSconfig(daneconfig *Config) *tls.Config {

	config := new(tls.Config)
	config.ServerName = daneconfig.Server.Name
	config.InsecureSkipVerify = true
	if daneconfig.NoVerify {
		return config
	}
	if daneconfig.TLSversion != 0 {
		config.MinVersion = daneconfig.TLSversion
		config.MaxVersion = daneconfig.TLSversion
	}
	if daneconfig.PKIXRootCA != nil {
		roots := x509.NewCertPool()
		_ = roots.AppendCertsFromPEM(daneconfig.PKIXRootCA)
		// Should emit log warning on failure to parse root CA data here.
		// Ideally we should return an error but that requires a function
		// signature change.
		config.RootCAs = roots
	}
	if daneconfig.ALPN != nil {
		config.NextProtos = daneconfig.ALPN
	}
	config.VerifyPeerCertificate = func(rawCerts [][]byte,
		verifiedChains [][]*x509.Certificate) error {
		return verifyServer(rawCerts, verifiedChains, config, daneconfig)
	}
	return config
}

// TLShandshake takes a network connection and a TLS Config structure,
// negotiates TLS on the connection and returns a TLS connection on
// success. It sets error to non-nil on failure.
func TLShandshake(conn net.Conn, config *tls.Config) (*tls.Conn, error) {

	tlsconn := tls.Client(conn, config)
	err := tlsconn.Handshake()
	return tlsconn, err
}

// DialTLS takes a pointer to an initialized dane Config structure,
// establishes and returns a TLS connection. The error return parameter
// is nil on success, and appropriately populated if not.
//
// DialTLS obtains a TLS config structure initialized with Dane
// verification callbacks, and connects to the server network address
// defined in Config using tls.DialWithDialer().
func DialTLS(daneconfig *Config) (*tls.Conn, error) {

	var err error
	var conn *tls.Conn

	config := GetTLSconfig(daneconfig)
	dialer := getDialer(daneconfig.TimeoutTCP)
	conn, err = tls.DialWithDialer(dialer, "tcp",
		daneconfig.Server.Address(), config)
	return conn, err
}

// DialStartTLS takes a pointer to an initialized dane Config structure,
// connects to the defined server, speaks the necessary application
// protocol preamble to activate STARTTLS, then negotiates TLS and returns
// the TLS connection. The error return parameter is nil on success, and
// appropriately populated if not.
//
// DialStartTLS obtains a TLS config structure, initialized with Dane
// verification callbacks, and connects to the server network address
// defined in Config using tls.DialWithDialer().
func DialStartTLS(daneconfig *Config) (*tls.Conn, error) {

	var err error
	var conn *tls.Conn

	config := GetTLSconfig(daneconfig)
	conn, err = StartTLS(config, daneconfig)
	return conn, err
}
