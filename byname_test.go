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

func TestConnectByName(t *testing.T) {

	var hostname = "www.example.com"
	var port = 443

	conn, config, err := ConnectByName(hostname, port)
	if err != nil {
		t.Fatalf("%s\n", err.Error())
	}
	fmt.Printf("ConnectByName: Success connecting to %s %d\n", hostname, port)
	if config.Okdane {
		fmt.Printf("DANE OK\n")
	} else if config.Okpkix {
		fmt.Printf("PKIX OK\n")
	}
	fmt.Printf("\n")
	conn.Close()
}
