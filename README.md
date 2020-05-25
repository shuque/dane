# dane
Go library for DANE authentication

Package dane provides a set of functions to perform DANE authentication
of a TLS server, with fall back to PKIX authentication if the server
does not advertise any signed DANE TLSA records. DANE is a protocol
that employs DNSSEC signed records ("TLSA") to authenticate X.509
certificates used in TLS and other protocols.

