package dane

import "crypto/x509"

//
// Config contains a DANE configuration for a single Server.
//
type Config struct {
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
	VerifiedChains [][]*x509.Certificate // Verified server Certificate Chains
}

//
// NewConfig initializes and returns a new dane Config structure.
//
func NewConfig() *Config {
	c := new(Config)
	c.DANE = true
	c.PKIX = true
	return c
}

//
// SetServer set the Server component of Config.
//
func (c *Config) SetServer(server *Server) {
	c.Server = server
}

//
// SetTLSA sets the TLSAinfo component of Config.
//
func (c *Config) SetTLSA(tlsa *TLSAinfo) {
	if tlsa != nil {
		tlsa.Uncheck()
		c.TLSA = tlsa
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
