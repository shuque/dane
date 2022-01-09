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
	fmt.Printf("ConnectByName: Success connecting to %s %s\n",
		hostname, config.Server.Address())
	if config.Okdane {
		fmt.Printf("DANE OK\n")
	} else if config.Okpkix {
		fmt.Printf("PKIX OK\n")
	}
	fmt.Printf("\n")
	conn.Close()
}

func TestConnectByNameAsync(t *testing.T) {

	var hostname = "www.example.com"
	var port = 443

	conn, config, err := ConnectByNameAsync(hostname, port)
	if err != nil {
		t.Fatalf("%s\n", err.Error())
	}
	fmt.Printf("ConnectByNameAsync: Success connecting to %s %s\n",
		hostname, config.Server.Address())
	if config.Okdane {
		fmt.Printf("DANE OK\n")
	} else if config.Okpkix {
		fmt.Printf("PKIX OK\n")
	}
	fmt.Printf("\n")
	conn.Close()
}

func TestConnectByNameAsync2(t *testing.T) {

	var hostname = "www.example.com"
	var port = 443

	conn, config, err := ConnectByNameAsync2(hostname, port, false)
	if err != nil {
		t.Fatalf("%s\n", err.Error())
	}
	fmt.Printf("ConnectByNameAsync2: Success connecting to %s %s\n",
		hostname, config.Server.Address())
	if config.Okdane {
		fmt.Printf("DANE OK\n")
	} else if config.Okpkix {
		fmt.Printf("PKIX OK\n")
	}
	fmt.Printf("\n")
	conn.Close()
}

func TestConnectByNameAsync2Fail(t *testing.T) {

	var hostname = "www.amazon.com"
	var port = 443

	conn, _, err := ConnectByNameAsync2(hostname, port, false)
	if err == nil {
		t.Fatalf("ConnectByNameAsync2 success for %s, expected failure\n", hostname)
	}
	_ = conn
	fmt.Printf("ConnectByNameAsync2: failed for %s: %s\n",
		hostname, err.Error())
	fmt.Printf("\n")
}
