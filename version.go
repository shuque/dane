//
// Package dane provides a set of functions to perform DANE authentication
// of a TLS server, with fall back to PKIX authentication if the server
// does not advertise any signed DANE TLSA records. DANE is a protocol
// that employs DNSSEC signed records ("TLSA") to authenticate X.509
// certificates used in TLS and other protocols.
//
// The package includes functions that will perform secure lookup of TLSA
// records and address records via a validating DNS resolver: GetTLSA() and
// GetAddresses(). Alternatively, if the calling application has obtained
// the TLSA record data by itself, it can populate the TLSAinfo structure
// defined in the library before calling the DANE TLS connection functions,
// DialTLSA() or DialStartTLS().
//
// The use of GetTLSA() and GetAddresses() requires the use of a validating
// DNS resolver, that sets the AD bit on authenticated responses. The
// GetResolver() function in this package, by default uses the set of resolvers
// defined in /etc/resolv.conf. This can be overridden by supplying a custom
// resolv.conf file, or by directly initializing a Resolver structure
// and placing it in the dane.Config structure. To be completely secure,
// it is important that system the code is running on has a secure connection
// to the validating resolver. (A future version of this library may perform
// stub DNSSEC validation itself, in which case it would only need to be able
// to communicate with a DNSSEC aware resolver, and not require a secure
// transport connection to it.)
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
// STARTLS is supported for SMTP, POP3, IMAP, and XMPP applications by setting
// the Appname and Servicename methods on the Config structure.
//
package dane

import "fmt"

// Version - current version number
var Version = VersionStruct{0, 1, 6}

// VersionStruct - version structure
type VersionStruct struct {
	Major, Minor, Patch int
}

// String representation of version
func (v VersionStruct) String() string {
	return fmt.Sprintf("%d.%d.%d", v.Major, v.Minor, v.Patch)
}
