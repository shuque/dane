package dane

import (
	"crypto/tls"
	"fmt"
)

//
// ConnectByName takes a hostname and port, resolves the addresses for
// the hostname (IPv6 followed by IPv4), and then attempts to connect to
// them and establish TLS. It returns a TLS connection and dane config for
// the first address that succeeds.
//
// Uses a default DANE configuration. For a custom DANE configuration,
// use the DialTLS or DialStartTLS functions instead.
//
func ConnectByName(hostname string, port int) (*tls.Conn, *Config, error) {

	var conn *tls.Conn

	resolver, err := GetResolver("")
	if err != nil {
		return nil, nil, fmt.Errorf("Error obtaining resolver address: %s", err.Error())
	}

	tlsa, err := GetTLSA(resolver, hostname, port)
	if err != nil {
		return nil, nil, fmt.Errorf("GetTLSA: %s", err.Error())
	}

	needSecure := (tlsa != nil)
	iplist, err := GetAddresses(resolver, hostname, needSecure)
	if err != nil {
		return nil, nil, fmt.Errorf("GetAddresses: %s", err.Error())
	}

	if len(iplist) == 0 {
		return nil, nil, fmt.Errorf("No addresses found")
	}

	for _, ip := range iplist {

		server := NewServer(hostname, ip, port)
		config := NewConfig()
		config.SetServer(server)
		config.SetTLSA(tlsa)
		conn, err = DialTLS(config)
		if err != nil {
			fmt.Printf("Connection failed to %s: %s\n", server.Address(), err.Error())
			continue
		}
		return conn, config, err
	}

	return conn, nil, fmt.Errorf("Failed to connect to any server address")
}
