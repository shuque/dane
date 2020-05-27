package dane

/*
 * Note: these test routines may not work unless you adapt this file
 * to use validating DNS resolvers and appropriately configured DANE TLS
 * servers you have access to.
 */

import (
	"testing"

	"github.com/miekg/dns"
)

var hostname = "www.example.com"

func TestSendQueryUDP(t *testing.T) {
	query := NewQuery(hostname, dns.TypeA, dns.ClassINET)
	msg, err := sendQueryUDP(query, resolver1)
	if err != nil {
		t.Fatalf("SendQueryUDP error: %s\n", err.Error())
	}
	_ = msg
}

func TestSendQueryTCP(t *testing.T) {
	query := NewQuery(hostname, dns.TypeA, dns.ClassINET)
	msg, err := sendQueryTCP(query, resolver1)
	if err != nil {
		t.Fatalf("SendQueryTCP error: %s\n", err.Error())
	}
	_ = msg
}

func TestGetAddresses(t *testing.T) {
	iplist, err := GetAddresses(resolver1, hostname, true)
	if err != nil {
		t.Fatalf("GetAddresses error: %s\n", err.Error())
	}
	if len(iplist) == 0 {
		t.Fatalf("GetAddresses: no addresses found for %s\n", hostname)
	}
}

func TestGetTLSA(t *testing.T) {
	tlsa, err := GetTLSA(resolver1, hostname, 443)
	if err != nil {
		t.Fatalf("GetTLSA error: %s\n", err.Error())
	}
	_ = tlsa
}
