# dane
Go library for DANE TLSA authentication

This repository contains two Go modules:

* **`github.com/shuque/dane`** (v1, at the repository root) is the
  original library, which the rest of this page up to Version 2
  describes. It looks up TLSA and address records, connects to TLS
  servers (with optional STARTTLS), and authenticates them with DANE.
  It can fall back to PKIX authentication.
* **`github.com/shuque/dane/v2`** (in the [`v2/`](v2/) directory) is a
  smaller, application-neutral rewrite. It looks up TLSA records and
  verifies certificate chains against them, for both server and client
  authentication. Client authentication includes TLS client
  authentication with DANE
  ([draft-ietf-dance-client-auth](https://datatracker.ietf.org/doc/draft-ietf-dance-client-auth/)).
  It never makes connections itself. See [Version 2](#version-2) below.

### Pre-requisites

* Go
* Go dns package from https://github.com/miekg/dns

### Documentation

Formatted documentation for this module can be found at:

https://pkg.go.dev/github.com/shuque/dane?tab=doc

### Description

Package dane provides a set of functions to perform DANE authentication
of a TLS server, with fall back to PKIX authentication if no DANE TLSA
records exist for the server. DANE is a protocol that employs DNSSEC signed
records ("TLSA") to authenticate X.509 certificates used in TLS and other
protocols. See RFC 6698 for details.

The dane.Config structure holds all the configured input parameters
for DANE authentication, including the server's name, address & port,
and the TLSA record set data. A new dane.Config structure has to be
instantiated for each DANE TLS server that needs to be authenticated.

The package includes functions that will perform secure lookup of TLSA
records and address records via a validating DNS resolver: GetTLSA() and
GetAddresses(). Alternatively, if the calling application has obtained
the TLSA record data by itself, it can populate the dane.Config's TLSA
structure itself.

The use of GetTLSA() and GetAddresses() requires the use of a validating
DNS resolver that sets the AD bit on authenticated responses. The
GetResolver() function in this package, by default uses the set of resolvers
defined in /etc/resolv.conf. This can be overridden by supplying a custom
resolv.conf file, or by directly initializing a Resolver structure
and placing it in the dane.Config. To be secure, it is important that system
the code is running on has a secure connection to the validating resolver.
(A future version of this library may perform stub DNSSEC validation itself,
in which case it would only need to be able to communicate with a DNSSEC aware
resolver, and not require a secure transport connection to it.)

The functions DialTLS() or DialStartTLS() take a dane.Config instance,
connect to the server, perform DANE authentication, and return a TLS
connection handle for subsequent use. DialStartTLS() will additionally
perform an application specific STARTTLS negotiation first. STARTTLS is
supported for the SMTP, POP3, IMAP, and XMPP applications by calling the
Appname and Servicename methods on the Config structure.

If no secure DANE TLSA records are found, or if the resolver doesn't
validate, this package will fallback to normal PKIX authentication.
Calling NoPKIXverify() on the Config structure will prevent this and
force a requirement for DANE authentication.

Per current spec (RFC 7671, Section 5.1), this library does not perform
certificate name checks for DANE-EE mode TLSA records, but this can be
overridden with the DaneEEname option. For Web applications it is sensible
to set the DaneEEname option to protect against Unknown Keyshare Attacks as
described in https://tools.ietf.org/html/draft-barnes-dane-uks-00 .

Also, per RFC 7672, Section 3.1.3, for SMTP STARTTLS the library ignores
PKIX-* mode TLSA records, since they are not recommended for use. This can
also be overridden by setting the SMTPAnyMode option.

After calling DialTLSA() or DialStartTLSA(), the dane.Config structure
is populated with additional diagnostic information, such as DANE and
PKIX authentication status, the verified certificate chains, and the
verification status of each DANE TLSA record processed.

If dane.Config.DiagMode is set to true, then DialTLSA() and DialStartTLSA()
will return a working TLS connection handle even if server authentication
fails (rather than an error), but will populate the dane.Config's DiagError
member with the appropriate error instead.


### Example code

The basic steps in summary form are:

```
import (
    ...
    "github.com/shuque/dane"
    )

// replace this with the name and port for a valid DANE TLS server
hostname := "www.example.com"
port := 443

resolver, err := dane.GetResolver()
tlsa, err := dane.GetTLSA(resolver, hostname, port)
iplist, err := dane.GetAddresses(resolver, hostname, true)

for _, ip := range iplist {
	daneconfig := dane.NewConfig(hostname, ip, 443)
	daneconfig.SetTLSA(tlsa)
	conn, err := dane.DialTLS(daneconfig)
	if err != nil {
		fmt.Printf("Result: FAILED: %s\n", err.Error())
		continue
	}
	if daneconfig.Okdane {
		fmt.Printf("Result: DANE OK\n")
	} else if daneconfig.Okpkix {
		fmt.Printf("Result: PKIX OK\n")
	} else {
		fmt.Printf("Result: FAILED\n")
	}
	//
	// do some stuff with the obtained TLS connection here
	//
	conn.Close()
}
```

The ConnectByName(), ConnectByNameAsync(), and ConnectByNameAsync2() functions
are simpler all-in-one functions that take a hostname and port argument, and then
lookup up TLSA records, connect to the first address associated with the hostname
that results in an authenticated connection, and returns the associated TLS connection
object.

GetHttpClient() returns a HTTP client structure (net/http.Client) configured to
do DANE authentication of a HTTPS server. The "pkixfallback" boolean argument specifies
whether or not to fallback to PKIX authentication if there are no secure TLSA records
published for the server.

### Version 2

`github.com/shuque/dane/v2` is in the [`v2/`](v2/) directory. It is a
separate Go module, so v1 users are unaffected. It is documented in
[v2/README.md](v2/README.md), which covers usage, the trust model,
server and client roles, lookup errors, and what was removed from v1.

For a complete example of a program using v2, see
[github.com/shuque/daneclient](https://github.com/shuque/daneclient), a
reference implementation of TLS client authentication with DANE.
