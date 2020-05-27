//
// Package dane provides a set of functions to perform DANE authentication
// of a TLS server, with fall back to PKIX authentication if the server
// does not advertise any signed DANE TLSA records. DANE is a protocol
// that employs DNSSEC signed records ("TLSA") to authenticate X.509
// certificates used in TLS and other protocols.
//
package dane

import "fmt"

// Version - current version number
var Version = VersionStruct{0, 1, 2}

// VersionStruct - version structure
type VersionStruct struct {
	Major, Minor, Patch int
}

// String representation of version
func (v VersionStruct) String() string {
	return fmt.Sprintf("%d.%d.%d", v.Major, v.Minor, v.Patch)
}
