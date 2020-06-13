package dane

/*
 * Note: these test routines may not work unless you adapt this file
 * to use validating DNS resolvers and appropriately configured DANE TLS
 * servers you have access to.
 */

import (
	"fmt"
	"net"
	"os"
	"testing"
)

var ip net.IP
var resolver1, resolver2 *Resolver

func TestMain(m *testing.M) {
	// validating resolver
	servers1 := []*Server{NewServer("", "8.8.8.8", 53)}
	resolver1 = NewResolver(servers1)
	// non-validating resolver
	resolver2, _ = GetResolver("")
	os.Exit(m.Run())
}

func TestDialTLS(t *testing.T) {
	testCases := []struct {
		host        string
		ip          string
		port        int
		resolver    *Resolver
		needsuccess bool
	}{
		{"www.example.com", "50.116.63.23", 443, resolver1, true},
		{"www.example.com", "50.116.63.23", 443, resolver2, true},
		{"www.amazon.com", "99.84.214.124", 443, resolver2, true},
		{"doth.example.com", "54.90.232.69", 853, resolver1, true},
		{"adns1.aws.example.com", "3.225.161.117", 443, resolver1, true},
		{"adns2.aws.example.com", "52.88.78.179", 443, resolver1, true},
		{"ctest1.aws.example.com", "3.225.161.117", 443, resolver1, true},
		{"ctest2.aws.example.com", "52.88.78.179", 443, resolver1, false},
		{"badhash.dane.example.com", "104.236.200.251", 443, resolver1, false},
		{"badparam.dane.example.com", "104.236.200.251", 443, resolver1, false},
		{"expiredsig.dane.example.com", "104.236.200.251", 443, resolver1, false},
	}
	for _, tc := range testCases {
		t.Run(fmt.Sprintf("## %s %s %d", tc.host, tc.ip, tc.port), func(t *testing.T) {
			defer fmt.Println("")
			daneconfig := NewConfig(tc.host, tc.ip, tc.port)
			server := daneconfig.Server
			fmt.Printf("## TLS: %s\n", server)
			tlsa, err := GetTLSA(tc.resolver, server.Name, server.Port)
			if err != nil {
				fmt.Printf("Result: FAILED: %s\n", err.Error())
				if tc.needsuccess {
					t.Fatalf("%s", err)
				}
				return
			}
			daneconfig.SetTLSA(tlsa)
			conn, err := DialTLS(daneconfig)
			if daneconfig.TLSA != nil {
				daneconfig.TLSA.Results()
			}
			if err != nil {
				fmt.Printf("Result: FAILED: %s\n", err.Error())
				if tc.needsuccess {
					t.Fatalf("DialTLS: %s.", err)
				}
				return
			}
			conn.Close()
			if daneconfig.Okdane {
				fmt.Printf("Result: DANE OK\n")
			} else if daneconfig.Okpkix {
				fmt.Printf("Result: PKIX OK\n")
			} else {
				fmt.Printf("Result: FAILED\n")
			}
		}) // end t.Run()
	}
}
