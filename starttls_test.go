package dane

/*
 * Note: these test routines may not work unless you adapt this file
 * to use validating DNS resolvers and appropriately configured DANE TLS
 * servers you have access to.
 */

import (
	"fmt"
	"testing"
)

func TestDialStartTLS(t *testing.T) {
	testCases := []struct {
		host        string
		ip          string
		port        int
		appname     string
		sname       string
		resolver    *Resolver
		needsuccess bool
	}{
		{"mail.example.com", "50.116.63.23", 25, "smtp", "", resolver1, true},
		{"mail.example.com", "50.116.63.23", 25, "blah", "", resolver1, false},
		{"locutus.example.com", "104.236.200.251", 143, "imap", "", resolver1, true},
		{"locutus.example.com", "104.236.200.251", 110, "pop3", "", resolver1, true},
	}
	for _, tc := range testCases {
		t.Run(fmt.Sprintf("## %s %s %d", tc.host, tc.ip, tc.port), func(t *testing.T) {
			defer fmt.Println("")
			daneconfig := NewConfig()
			server := NewServer(tc.host, tc.ip, tc.port)
			daneconfig.SetServer(server)
			daneconfig.SetAppName(tc.appname)
			daneconfig.SetServiceName(tc.sname)
			daneconfig.NoPKIXfallback()

			fmt.Printf("## STARTTLS: %s %s %s\n", server, tc.appname, tc.sname)
			tlsa, err := GetTLSA(tc.resolver, server.Name, server.Port)
			if err != nil {
				fmt.Printf("Result: FAILED: %s\n", err.Error())
				if tc.needsuccess {
					t.Fatalf("%s", err)
				}
				return
			}
			daneconfig.SetTLSA(tlsa)
			conn, err := DialStartTLS(daneconfig)
			if daneconfig.Transcript != "" {
				fmt.Printf("%s", daneconfig.Transcript)
			}
			if daneconfig.TLSA != nil {
				daneconfig.TLSA.Results()
			}
			if err != nil {
				fmt.Printf("Result: FAILED: %s\n", err.Error())
				if tc.needsuccess {
					t.Fatalf("DialStartTLS: %s.", err)
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
