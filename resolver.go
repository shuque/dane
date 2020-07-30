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
	defaultDNSTimeout          = 2
	defaultDNSRetries          = 3
	defaultTCPTimeout          = 3
	defaultResolverPort        = 53
	defaultResolvConf          = "/etc/resolv.conf"
	defaultBufsize      uint16 = 1460
)

//
// Resolver contains a DNS resolver configuration
//
type Resolver struct {
	Servers      []*Server     // list of resolvers
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
func NewResolver(servers []*Server) *Resolver {
	r := new(Resolver)
	r.Servers = servers
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
// GetResolver obtains the 1st resolver address from the system
// default resolver configuration (/etc/resolv.conf), or from a custom
// resolver configuration file (resconf), if it is set. Returns an
// initialized Resolver structure on success, otherwise sets error
// to non-nil.
//
func GetResolver(resconf string) (*Resolver, error) {

	var ip net.IP
	var resolver *Resolver
	var servers []*Server

	if resconf == "" {
		resconf = defaultResolvConf
	}
	c, err := dns.ClientConfigFromFile(resconf)
	if err != nil {
		return nil, err
	}

	for _, s := range c.Servers {
		ip = net.ParseIP(s)
		servers = append(servers, NewServer("", ip, defaultResolverPort))
	}
	resolver = NewResolver(servers)
	return resolver, err
}
