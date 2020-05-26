package dane

import (
	"net"
	"time"

	"github.com/miekg/dns"
)

//
// DNS resolver defaults
//
var (
	defaultDNSTimeout                 = 3
	defaultDNSRetries                 = 3
	defaultTCPTimeout                 = 4
	defaultResolverPort               = 53
	defaultResolvConf                 = "/etc/resolv.conf"
	timeoutTCP          time.Duration = time.Second * 5
	retries                           = 3
	defaultBufsize      uint16        = 1460
)

//
// Resolver contains a DNS resolver configuration
//
type Resolver struct {
	Ipaddr       net.IP        // resolver IP address
	Port         int           // resolver port number
	Rdflag       bool          // set RD flag
	Adflag       bool          // set AD flag
	Cdflag       bool          // set CD flag
	Timeout      time.Duration // query timeout
	Retries      int           // query retries
	Payload      uint16        // EDNS0 UDP payload size
	IPv6         bool          // lookup AAAA records in getAddresses()
	IPv4         bool          // look A records in getAddresses()
	Pkixfallback bool          // whether to fallback to PKIX in getTLSA()
}

//
// NewResolver initializes a new Resolver structure from a given IP
// address (net.IP) and port number.
//
func NewResolver(ip net.IP, port int) *Resolver {
	r := new(Resolver)
	r.Ipaddr = ip
	r.Port = port
	r.Rdflag = true
	r.Adflag = true
	r.Timeout = time.Second * time.Duration(defaultDNSTimeout)
	r.Retries = defaultDNSRetries
	r.Payload = defaultBufsize
	r.IPv6 = true
	r.IPv4 = true
	r.Pkixfallback = true
	return r
}

//
// Address returns an address string for the Resolver.
//
func (r *Resolver) Address() string {
	return addressString(r.Ipaddr, r.Port)
}

//
// GetResolver obtains the 1st resolver address from the system
// default resolver configuration (/etc/resolv.conf), or from a custom
// resolver configuration file (resconf), if it is set. Returns an
// initialized Resolver structure on success, otherwise sets error
// to non-nil.
//
func GetResolver(resconf string) (*Resolver, error) {

	var ip net.IP
	var resolver *Resolver

	if resconf == "" {
		resconf = defaultResolvConf
	}
	c, err := dns.ClientConfigFromFile(resconf)
	if err == nil {
		ip = net.ParseIP(c.Servers[0])
		resolver = NewResolver(ip, defaultResolverPort)
	}
	return resolver, err
}
