# dane
Go library for DANE authentication

### Pre-requisites

* Go
* Go dns package from https://github.com/miekg/dns

### Description

dane v0.1.2

Package dane provides a set of functions to perform DANE authentication
of a TLS server, with fall back to PKIX authentication if the server
does not advertise any signed DANE TLSA records. DANE is a protocol
that employs DNSSEC signed records ("TLSA") to authenticate X.509
certificates used in TLS and other protocols.

DANE authentication requires the use of a validating DNS resolver,
that sets the AD bit on authenticated responses. The GetResolver()
function in this package, by default uses the 1st resolver listed
in /etc/resolv.conf. This can be overridden by supplying a custom
resolv.conf file. Or by directly initializing a Resolver structure
and placing it in the dane.Config structure. If no secure DANE TLSA
records are found, or if the resolver doesn't validate, this package
will fallback to normal PKIX authentication. Calling NoPKIXverify()
on the Config structure will prevent this and force a requirement
for DANE authentication.

Per current spec, this library does not perform certificate hostname
checks for DANE-EE mode TLSA records, but this can overridden with the
DaneEEname config option. For SMTP STARTTLS the library ignores PKIX-*
mode TLSA records, unless the SMTPAnyMode option is set.

STARTLS is supported for SMTP, POP3, IMAP, and XMPP by setting the
Appname and Servicename methods on the Config structure.

### Example code

Example code that uses this library can be found in example_test.go.
A detailed example program that uses the library can be found at
https://github.com/shuque/gotls

### Documentation

Formatted documentation for this module can be found at:

https://pkg.go.dev/github.com/shuque/dane?tab=doc
