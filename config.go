package dane

import (
	"crypto/x509"
)

//
// Config contains a DANE configuration for a single Server.
//
type Config struct {
	DiagMode       bool                  // Diagnostic mode
	DiagError      error                 // Holds possible error in Diagnostic mode
	Server         *Server               // Server structure (name, ip, port)
	NoVerify       bool                  // Don't verify server certificate
	DaneEEname     bool                  // Do name checks even for DANE-EE mode
	SMTPAnyMode    bool                  // Allow any DANE modes for SMTP
	Appname        string                // STARTTLS application name
	Servicename    string                // Servicename, if different from server
	Transcript     string                // StartTLS transcript
	DANE           bool                  // do DANE authentication
	PKIX           bool                  // fall back to PKIX authentication
	Okdane         bool                  // DANE authentication result
	Okpkix         bool                  // PKIX authentication result
	TLSA           *TLSAinfo             // TLSA RRset information
	PeerChain      []*x509.Certificate   // Peer Certificate Chain
	VerifiedChains [][]*x509.Certificate // Verified server Certificate Chains
}

//
// NewConfig initializes and returns a new dane Config structure
// for the given server name, ip address and port. The IP address
// can be specified either as a string or a net.IP structure. The
// initialized config does DANE authentication with fallback to PKIX.
//
func NewConfig(hostname string, ip interface{}, port int) *Config {
	c := new(Config)
	c.DANE = true
	c.PKIX = true
	c.Server = NewServer(hostname, ip, port)
	return c
}

//
// SetServer set the Server component of Config.
//
func (c *Config) SetServer(server *Server) {
	c.Server = server
}

//
// SetTLSA sets the TLSAinfo component of Config. A copy of the TLSAinfo
// structure is made, to permit concurrent use of the structure that may
// independently change the (reset) checking bits.
//
func (c *Config) SetTLSA(tlsa *TLSAinfo) {
	if tlsa != nil {
		c.TLSA = tlsa.Copy()
		c.TLSA.Uncheck()
	}
}

//
// SetAppName sets the STARTTLS application name.
//
func (c *Config) SetAppName(appname string) {
	c.Appname = appname
}

//
// SetServiceName sets the STARTTLS service name.
//
func (c *Config) SetServiceName(servicename string) {
	c.Servicename = servicename
}

//
// NoPKIXfallback sets Config to not allow PKIX fallback. Only DANE
// authentication is permitted.
//
func (c *Config) NoPKIXfallback() {
	c.PKIX = false
}

//
// SetDiagMode sets the Diagnostic mode.
//
func (c *Config) SetDiagMode(value bool) {
	c.DiagMode = value
}
