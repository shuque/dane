package dane_test

/*
 * An example program.
 */

import (
	"fmt"
	"log"

	"github.com/shuque/dane"
)

func Example() {

	var daneconfig *dane.Config

	servers := []*dane.Server{dane.NewServer("", "8.8.8.8", 53)}
	resolver := dane.NewResolver(servers)
	hostname := "www.example.com"
	tlsa, err := dane.GetTLSA(resolver, hostname, 443)
	if err != nil {
		log.Fatalf("%s", err)
	}
	if tlsa == nil {
		log.Fatalf("No TLSA records found, where expected.")
	}
	iplist, err := dane.GetAddresses(resolver, hostname, true)
	if err != nil {
		log.Fatalf("%s", err)
	}
	if len(iplist) < 1 {
		log.Fatalf("Got less than expected addresses.")
	}
	for _, ip := range iplist {
		daneconfig = dane.NewConfig(hostname, ip, 443)
		daneconfig.SetTLSA(tlsa)
		conn, err := dane.DialTLS(daneconfig)
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
