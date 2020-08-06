package dane

import (
	"crypto/tls"
	"fmt"
	"net"
	"sync"
	"time"
)

//
// Response - response information
//
type Response struct {
	config *Config
	conn   *tls.Conn
	err    error
}

// IPv6 connect headstart (delay IPv4 connections by this amount)
var IPv6Headstart = 25 * time.Millisecond

// For goroutine communications and synchronization
var wg sync.WaitGroup
var numParallel uint16 = 20
var tokens = make(chan struct{}, int(numParallel))
var results = make(chan *Response)

//
// ConnectByName takes a hostname and port, resolves the addresses for
// the hostname (IPv6 followed by IPv4), and then attempts to connect to
// them and establish TLS using DANE or PKIX authentication - DANE is
// attempted if there are secure TLSA records, otherwise it falls back to
// PKIX authentication. It returns a TLS connection and dane config for
// the first address that succeeds.
//
// Uses a default DANE configuration. For a custom DANE configuration,
// use the DialTLS or DialStartTLS functions instead.
//
func ConnectByName(hostname string, port int) (*tls.Conn, *Config, error) {

	var conn *tls.Conn

	resolver, err := GetResolver("")
	if err != nil {
		return nil, nil, fmt.Errorf("error obtaining resolver address: %s", err.Error())
	}

	tlsa, err := GetTLSA(resolver, hostname, port)
	if err != nil {
		return nil, nil, err
	}

	needSecure := (tlsa != nil)
	iplist, err := GetAddresses(resolver, hostname, needSecure)
	if err != nil {
		return nil, nil, err
	}

	if len(iplist) == 0 {
		return nil, nil, fmt.Errorf("%s: no addresses found", hostname)
	}

	for _, ip := range iplist {
		config := NewConfig(hostname, ip, port)
		config.SetTLSA(tlsa)
		conn, err = DialTLS(config)
		if err != nil {
			fmt.Printf("Connection failed to %s: %s\n", config.Server.Address(),
				err.Error())
			continue
		}
		return conn, config, err
	}

	return conn, nil, fmt.Errorf("failed to connect to any server address for %s",
		hostname)
}

//
// ConnectByNameAsync is an async version of ConnectByName that tries
// to connect to all server addresses in parallel, and returns the first
// successful connection. IPv4 connections are intentionally delayed by
// an IPv6HeadStart amount of time.
//
func ConnectByNameAsync(hostname string, port int) (*tls.Conn, *Config, error) {

	var conn *tls.Conn
	var ip net.IP

	resolver, err := GetResolver("")
	if err != nil {
		return nil, nil, fmt.Errorf("error obtaining resolver address: %s", err.Error())
	}

	tlsa, err := GetTLSA(resolver, hostname, port)
	if err != nil {
		return nil, nil, err
	}

	needSecure := (tlsa != nil)
	iplist, err := GetAddresses(resolver, hostname, needSecure)
	if err != nil {
		return nil, nil, err
	}

	if len(iplist) == 0 {
		return nil, nil, fmt.Errorf("%s: no addresses found", hostname)
	}

	go func() {
		for _, ip = range iplist {
			wg.Add(1)
			tokens <- struct{}{}
			go func(hostname string, ip net.IP, port int) {
				defer wg.Done()
				config := NewConfig(hostname, ip, port)
				config.SetTLSA(tlsa)
				ip4 := ip.To4()
				if ip4 != nil {
					time.Sleep(IPv6Headstart)
				}
				conn, err = DialTLS(config)
				<-tokens
				results <- &Response{config: config, conn: conn, err: err}
			}(hostname, ip, port)
		}
		wg.Wait()
		close(results)
	}()

	for r := range results {
		if r.err == nil {
			return r.conn, r.config, nil
		}
	}
	return conn, nil, fmt.Errorf("failed to connect to any server address for %s",
		hostname)
}
