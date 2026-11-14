package dane

import (
	"crypto/tls"
	"errors"
	"net"
	"testing"

	"github.com/miekg/dns"
)

// Save the original sendQuery function so we can restore it after each test
var originalSendQuery = sendQueryFn

// Save the original TLSDial function so we can restore it after each test
var originalTLSDial = tlsDialFn

func TestGetTLSAWithDNSError(t *testing.T) {
	sendQueryFn = func(query *Query, resolver *Resolver) (*dns.Msg, error) {
		return nil, errors.New("DNS server error")
	}
	defer func() { sendQueryFn = originalSendQuery }()

	resolver := NewResolver([]*Server{})
	hostname := "example.com"
	port := 443

	_, err := GetTLSA(resolver, hostname, port)
	if err == nil {
		t.Error("Expected error from GetTLSA, got nil")
	}
}

func TestGetTLSAWithNoRecords(t *testing.T) {
	sendQueryFn = func(query *Query, resolver *Resolver) (*dns.Msg, error) {
		return &dns.Msg{
			MsgHdr: dns.MsgHdr{Rcode: dns.RcodeSuccess, AuthenticatedData: true},
			Answer: []dns.RR{},
		}, nil
	}
	defer func() { sendQueryFn = originalSendQuery }()

	resolver := NewResolver([]*Server{})
	hostname := "example.com"
	port := 443

	tlsa, err := GetTLSA(resolver, hostname, port)
	if err != nil {
		t.Fatalf("GetTLSA failed: %v", err)
	}

	if tlsa != nil {
		t.Fatal("Expected nil TLSA info when no records and PKIX fallback enabled")
	}
}

func TestGetAddressesWithDNSError(t *testing.T) {
	sendQueryFn = func(query *Query, resolver *Resolver) (*dns.Msg, error) {
		return nil, errors.New("DNS server error")
	}
	defer func() { sendQueryFn = originalSendQuery }()

	resolver := NewResolver([]*Server{})
	hostname := "example.com"
	ipv6 := true

	_, err := GetAddresses(resolver, hostname, ipv6)
	if err == nil {
		t.Error("Expected error from GetAddresses, got nil")
	}
}

func TestGetAddressesWithNoRecords(t *testing.T) {
	sendQueryFn = func(query *Query, resolver *Resolver) (*dns.Msg, error) {
		return &dns.Msg{
			MsgHdr: dns.MsgHdr{Rcode: dns.RcodeSuccess, AuthenticatedData: true},
			Answer: []dns.RR{},
		}, nil
	}
	defer func() { sendQueryFn = originalSendQuery }()

	resolver := NewResolver([]*Server{})
	hostname := "example.com"
	ipv6 := true

	iplist, err := GetAddresses(resolver, hostname, ipv6)
	if err != nil {
		t.Fatalf("GetAddresses failed: %v", err)
	}

	if len(iplist) != 0 {
		t.Errorf("Expected 0 IP addresses, got %d", len(iplist))
	}
}

func TestGetAddressesWithIPv4Only(t *testing.T) {
	sendQueryFn = func(query *Query, resolver *Resolver) (*dns.Msg, error) {
		if query.Type == dns.TypeA {
			return &dns.Msg{
				MsgHdr: dns.MsgHdr{Rcode: dns.RcodeSuccess, AuthenticatedData: true},
				Answer: []dns.RR{
					&dns.A{
						Hdr: dns.RR_Header{
							Name:   "example.com.",
							Rrtype: dns.TypeA,
							Class:  dns.ClassINET,
						},
						A: net.ParseIP("192.0.2.1"),
					},
				},
			}, nil
		}
		return &dns.Msg{
			MsgHdr: dns.MsgHdr{Rcode: dns.RcodeSuccess, AuthenticatedData: true},
			Answer: []dns.RR{},
		}, nil
	}
	defer func() { sendQueryFn = originalSendQuery }()

	resolver := NewResolver([]*Server{})
	hostname := "example.com"
	ipv6 := true

	iplist, err := GetAddresses(resolver, hostname, ipv6)
	if err != nil {
		t.Fatalf("GetAddresses failed: %v", err)
	}

	if len(iplist) != 1 {
		t.Errorf("Expected 1 IP address, got %d", len(iplist))
	}

	if !iplist[0].Equal(net.ParseIP("192.0.2.1")) {
		t.Errorf("Expected IP 192.0.2.1, got %s", iplist[0])
	}
}

func TestGetAddressesWithIPv6Only(t *testing.T) {
	sendQueryFn = func(query *Query, resolver *Resolver) (*dns.Msg, error) {
		if query.Type == dns.TypeAAAA {
			return &dns.Msg{
				MsgHdr: dns.MsgHdr{Rcode: dns.RcodeSuccess, AuthenticatedData: true},
				Answer: []dns.RR{
					&dns.AAAA{
						Hdr: dns.RR_Header{
							Name:   "example.com.",
							Rrtype: dns.TypeAAAA,
							Class:  dns.ClassINET,
						},
						AAAA: net.ParseIP("2001:db8::1"),
					},
				},
			}, nil
		}
		return &dns.Msg{
			MsgHdr: dns.MsgHdr{Rcode: dns.RcodeSuccess, AuthenticatedData: true},
			Answer: []dns.RR{},
		}, nil
	}
	defer func() { sendQueryFn = originalSendQuery }()

	resolver := NewResolver([]*Server{})
	hostname := "example.com"
	ipv6 := true

	iplist, err := GetAddresses(resolver, hostname, ipv6)
	if err != nil {
		t.Fatalf("GetAddresses failed: %v", err)
	}

	if len(iplist) != 1 {
		t.Errorf("Expected 1 IP address, got %d", len(iplist))
	}

	if !iplist[0].Equal(net.ParseIP("2001:db8::1")) {
		t.Errorf("Expected IP 2001:db8::1, got %s", iplist[0])
	}
}

func TestGetAddressesWithBothIPv4AndIPv6(t *testing.T) {
	sendQueryFn = func(query *Query, resolver *Resolver) (*dns.Msg, error) {
		if query.Type == dns.TypeA {
			return &dns.Msg{
				MsgHdr: dns.MsgHdr{Rcode: dns.RcodeSuccess, AuthenticatedData: true},
				Answer: []dns.RR{
					&dns.A{
						Hdr: dns.RR_Header{
							Name:   "example.com.",
							Rrtype: dns.TypeA,
							Class:  dns.ClassINET,
						},
						A: net.ParseIP("192.0.2.1"),
					},
				},
			}, nil
		}
		if query.Type == dns.TypeAAAA {
			return &dns.Msg{
				MsgHdr: dns.MsgHdr{Rcode: dns.RcodeSuccess, AuthenticatedData: true},
				Answer: []dns.RR{
					&dns.AAAA{
						Hdr: dns.RR_Header{
							Name:   "example.com.",
							Rrtype: dns.TypeAAAA,
							Class:  dns.ClassINET,
						},
						AAAA: net.ParseIP("2001:db8::1"),
					},
				},
			}, nil
		}
		return &dns.Msg{
			MsgHdr: dns.MsgHdr{Rcode: dns.RcodeSuccess, AuthenticatedData: true},
			Answer: []dns.RR{},
		}, nil
	}
	defer func() { sendQueryFn = originalSendQuery }()

	resolver := NewResolver([]*Server{})
	hostname := "example.com"
	ipv6 := true

	iplist, err := GetAddresses(resolver, hostname, ipv6)
	if err != nil {
		t.Fatalf("GetAddresses failed: %v", err)
	}

	if len(iplist) != 2 {
		t.Errorf("Expected 2 IP addresses, got %d", len(iplist))
	}

	// Check that both IPv4 and IPv6 addresses are present
	foundIPv4 := false
	foundIPv6 := false
	for _, ip := range iplist {
		if ip.Equal(net.ParseIP("192.0.2.1")) {
			foundIPv4 = true
		}
		if ip.Equal(net.ParseIP("2001:db8::1")) {
			foundIPv6 = true
		}
	}

	if !foundIPv4 {
		t.Error("IPv4 address not found in results")
	}
	if !foundIPv6 {
		t.Error("IPv6 address not found in results")
	}
}

func TestDialTLSSuccess(t *testing.T) {
	tlsDialFn = func(dialer *net.Dialer, network, addr string, config *tls.Config) (*tls.Conn, error) {
		return &tls.Conn{}, nil
	}
	defer func() { tlsDialFn = originalTLSDial }()

	config := NewConfig("example.com", "192.0.2.1", 443)
	conn, err := DialTLS(config)
	if err != nil {
		t.Fatalf("DialTLS failed: %v", err)
	}
	if conn == nil {
		t.Fatal("DialTLS returned nil connection")
	}
}

func TestDialTLSTLSHandshakeFailure(t *testing.T) {
	tlsDialFn = func(dialer *net.Dialer, network, addr string, config *tls.Config) (*tls.Conn, error) {
		return nil, errors.New("TLS handshake failure")
	}
	defer func() { tlsDialFn = originalTLSDial }()

	config := NewConfig("example.com", "192.0.2.1", 443)
	conn, err := DialTLS(config)
	if err == nil {
		t.Fatal("Expected error from DialTLS, got nil")
	}
	if conn != nil {
		t.Fatal("DialTLS returned non-nil connection on error")
	}
}

func TestDialTLSNetworkFailure(t *testing.T) {
	tlsDialFn = func(dialer *net.Dialer, network, addr string, config *tls.Config) (*tls.Conn, error) {
		return nil, errors.New("network connection failure")
	}
	defer func() { tlsDialFn = originalTLSDial }()

	config := NewConfig("example.com", "192.0.2.1", 443)
	conn, err := DialTLS(config)
	if err == nil {
		t.Fatal("Expected error from DialTLS, got nil")
	}
	if conn != nil {
		t.Fatal("DialTLS returned non-nil connection on error")
	}
}
