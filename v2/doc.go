// Package dane performs application-neutral DANE TLSA lookup and
// verification (RFC 6698, RFC 7671) for both server and client
// authentication. It verifies certificate chains against TLSA records;
// it never makes connections itself.
//
// Trust model: use a trusted validating DNSSEC resolver, ideally on
// loopback. The AD bit in its responses is trusted.
//
// Two roles are supported. For client authentication, the ClientName is
// queried verbatim as the TLSA owner name. For server authentication,
// the owner name is _port._proto.host.
package dane
