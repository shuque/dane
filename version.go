//
// Package dane provides a set of functions to perform DANE authentication
// of a TLS server, with fall back to PKIX authentication if no DANE TLSA
// records exist for the server. DANE is a protocol that employs DNSSEC signed
// records ("TLSA") to authenticate X.509 certificates used in TLS and other
// protocols. See RFC 6698 for details.
//
// The dane.Config structure holds all the configured input parameters
// for DANE authentication, including the server's name, address & port,
// and the TLSA record set data. A new dane.Config structure has to be
// instantiated for each DANE TLS server that needs to be authenticated.
//
// The package includes functions that will perform secure lookup of TLSA
// records and address records via a validating DNS resolver: GetTLSA() and
// GetAddresses(). Alternatively, if the calling application has obtained
// the TLSA record data by itself, it can populate the dane.Config's TLSA
// structure itself.
//
// The use of GetTLSA() and GetAddresses() requires the use of a validating
// DNS resolver that sets the AD bit on authenticated responses. The
// GetResolver() function in this package, by default uses the set of resolvers
// defined in /etc/resolv.conf. This can be overridden by supplying a custom
// resolv.conf file, or by directly initializing a Resolver structure
// and placing it in the dane.Config. To be secure, it is important that system
// the code is running on has a secure connection to the validating resolver.
// (A future version of this library may perform stub DNSSEC validation itself,
// in which case it would only need to be able to communicate with a DNSSEC aware
// resolver, and not require a secure transport connection to it.)
//
// The functions DialTLS() or DialStartTLS() take a dane.Config instance,
// connect to the server, perform DANE authentication, and return a TLS
// connection handle for subsequent use. DialStartTLS() will additionally
// perform an application specific STARTTLS negotiation first. STARTTLS is
// supported for the SMTP, POP3, IMAP, and XMPP applications by calling the
// Appname and Servicename methods on the Config structure.
//
// If no secure DANE TLSA records are found, or if the resolver doesn't
// validate, this package will fallback to normal PKIX authentication.
// Calling NoPKIXverify() on the Config structure will prevent this and
// force a requirement for DANE authentication.
//
// Per current spec (RFC 7671, Section 5.1), this library does not perform
// certificate name checks for DANE-EE mode TLSA records, but this can be
// overridden with the DaneEEname option. For Web applications it is sensible
// to set the DaneEEname option to protect against Unknown Keyshare Attacks as
// described in https://tools.ietf.org/html/draft-barnes-dane-uks-00 .
//
// Also, per RFC 7672, Section 3.1.3, for SMTP STARTTLS the library ignores
// PKIX-* mode TLSA records, since they are not recommended for use. This can
// also be overridden by setting the SMTPAnyMode option.
//
// After calling DialTLSA() or DialStartTLSA(), the dane.Config structure
// is populated with additional diagnostic information, such as DANE and
// PKIX authentication status, the verified certificate chains, and the
// verification status of each DANE TLSA record processed.
//
// If dane.Config.DiagMode is set to true, then DialTLSA() and DialStartTLSA()
// will return a working TLS connection handle even if server authentication
// fails (rather than an error), but will populate the dane.Config's DiagError
// member with the appropriate error instead.
//
// The ConnectByName(), ConnectByNameAsync(), and ConnectByNameAsync2() functions
// are simpler all-in-one functions that take a hostname and port argument, and then
// lookup up TLSA records, connect to the first address associated with the hostname
// that results in an authenticated connection, and returns the associated TLS connection
// object.
//
// GetHttpClient() returns a HTTP client structure (net/http.Client) configured to
// do DANE authentication of a HTTPS server. The "pkixfallback" boolean argument
// specifies whether or not to fallback to PKIX authentication if there are no secure
// TLSA records published for the server.
//

package dane

import "fmt"

// Version - current version number
var Version = VersionStruct{0, 1, 13}

// VersionStruct - version structure
type VersionStruct struct {
	Major, Minor, Patch int
}

// String representation of version
func (v VersionStruct) String() string {
	return fmt.Sprintf("%d.%d.%d", v.Major, v.Minor, v.Patch)
}
