package dane

import (
	"fmt"
	"net"
)

//
// Server contains a information about a single TLS server: hostname,
// IP address (net.IP) and port number.
//
type Server struct {
	Name   string
	Ipaddr net.IP
	Port   int
}

//
// NewServer returns an initialized Server structure from given
// name, IP address, and port.
//
func NewServer(name string, ip interface{}, port int) *Server {
	s := new(Server)
	s.Name = name
	switch ip.(type) {
	case net.IP:
		s.Ipaddr = ip.(net.IP)
	case string:
		s.Ipaddr = net.ParseIP(ip.(string))
	}
	s.Port = port
	return s
}

//
// Address returns an address string for the Server.
//
func (s *Server) Address() string {
	return addressString(s.Ipaddr, s.Port)
}

//
// String returns a string representation of Server.
//
func (s *Server) String() string {
	return fmt.Sprintf("%s %s", s.Name, s.Address())
}
