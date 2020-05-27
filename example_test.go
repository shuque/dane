package dane

/*
 * An example program.
 */

import (
	"fmt"
	"log"
	"net"
)

func Example() {
	var daneconfig *Config

	resolver := NewResolver(net.ParseIP("8.8.8.8"), 53)
	hostname := "www.example.com"
	tlsa, err := GetTLSA(resolver, hostname, 443)
	if err != nil {
		log.Fatalf("%s", err)
	}
	if tlsa == nil {
		log.Fatalf("No TLSA records found, where expected.")
	}
	iplist, err := GetAddresses(resolver1, hostname, true)
	if err != nil {
		log.Fatalf("%s", err)
	}
	if len(iplist) < 1 {
		log.Fatalf("Got less than expected addresses.")
	}
	for _, ip := range iplist {
		daneconfig = NewConfig(hostname, ip, 443)
		daneconfig.SetTLSA(tlsa)
		conn, err := DialTLS(daneconfig)
		if daneconfig.TLSA != nil {
			daneconfig.TLSA.Results()
		}
		if err != nil {
			fmt.Printf("Result: FAILED: %s\n", err.Error())
			continue
		}
		conn.Close()
		if daneconfig.Okdane {
			fmt.Printf("Result: DANE OK\n")
		} else if daneconfig.Okpkix {
			fmt.Printf("Result: PKIX OK\n")
		} else {
			fmt.Printf("Result: FAILED\n")
		}

	}
}
