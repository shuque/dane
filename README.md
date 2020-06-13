# dane
Go library for DANE authentication

### Pre-requisites

* Go
* Go dns package from https://github.com/miekg/dns

### Description

dane v0.1.4

Package dane provides a set of functions to perform DANE authentication
of a TLS server, with fall back to PKIX authentication if the server
does not advertise any signed DANE TLSA records. DANE is a protocol
that employs DNSSEC signed records ("TLSA") to authenticate X.509
certificates used in TLS and other protocols.

The package includes functions that will perform secure lookup of TLSA
records and address records via a validating DNS resolver: GetTLSA() and
GetAddresses(). Alternatively, if the calling application has obtained
the TLSA record data by itself, it can populate the TLSAinfo structure
defined in the library before calling the DANE TLS connection functions.

The use of GetTLSA() and GetAddresses() requires the use of a validating
DNS resolver, that sets the AD bit on authenticated responses. The
GetResolver() function in this package, by default uses the set of resolvers
defined in /etc/resolv.conf. This can be overridden by supplying a custom
resolv.conf file, or by directly initializing a Resolver structure
and placing it in the dane.Config structure. To be completely secure,
it is important that system the code is running on has a secure connection
to the validating resolver. (A future version of this library may perform
stub DNSSEC validation itself, in which case it would only need to be able
to communicate with a DNSSEC aware resolver, and not require a secure
transport connection to it.)

If no secure DANE TLSA records are found, or if the resolver doesn't
validate, this package will fallback to normal PKIX authentication.
Calling NoPKIXverify() on the Config structure will prevent this and
force a requirement for DANE authentication.

Per current spec, this library does not perform certificate hostname
checks for DANE-EE mode TLSA records, but this can overridden with the
DaneEEname config option. For SMTP STARTTLS the library ignores PKIX-*
mode TLSA records, unless the SMTPAnyMode option is set.

STARTLS is supported for SMTP, POP3, IMAP, and XMPP by setting the
Appname and Servicename methods on the Config structure.

### Example code

A detailed diagnostic tool that uses the library can be found at
https://github.com/shuque/gotls

The basic steps in summary form are:

```
import (
    ...
    "github.com/shuque/dane"
    )

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
    // do some stuff
	conn.Close()
	if daneconfig.Okdane {
		fmt.Printf("Result: DANE OK\n")
	} else if daneconfig.Okpkix {
		fmt.Printf("Result: PKIX OK\n")
	} else {
		fmt.Printf("Result: FAILED\n")
	}
}
```

The ConnectByName() function is a simpler all-in-one function that takes a
hostname and port argument, and then lookups up TLSA records, connects to
the first address associated with the hostname that results in an
authenticated connection, and returns the associated TLS connection object.


### Documentation

Formatted documentation for this module can be found at:

https://pkg.go.dev/github.com/shuque/dane?tab=doc
