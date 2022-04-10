package dane

import (
	"crypto/x509"
	"encoding/pem"
	"net"
	"strconv"
	"strings"
	"time"
)

//
// addressString returns address string from the given IP address and
// port.
//
func addressString(ipaddress net.IP, port int) string {

	addr := ipaddress.String()
	if !strings.Contains(addr, ":") {
		return addr + ":" + strconv.Itoa(port)
	}
	return "[" + addr + "]" + ":" + strconv.Itoa(port)
}

//
// getTCPDialer returns a net.Dialer object, initialized with the given
// timeout (in seconds).
//
func getDialer(timeout int) *net.Dialer {

	dialer := new(net.Dialer)
	dialer.Timeout = time.Second * time.Duration(timeout)
	return dialer
}

//
// getTCPconn establishes a TCP connection to the given address and port.
// Returns a TCP connection (net.Conn) on success. Populates error on
// failure.
//
func getTCPconn(address net.IP, port int, timeout int) (net.Conn, error) {

	dialer := getDialer(timeout)
	conn, err := dialer.Dial("tcp", addressString(address, port))
	return conn, err
}

//
// CertToPEMBytes returns PEM encoded bytes corresponding to the given
// x.509 certificate.
//
func CertToPEMBytes(cert *x509.Certificate) []byte {

	block := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	}
	return pem.EncodeToMemory(block)
}
