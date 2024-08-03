package dane

import (
	"errors"
	"fmt"
	"net"

	"github.com/miekg/dns"
)

// Query contains parameters of a DNS query: name, type, and class.
type Query struct {
	Name  string
	Type  uint16
	Class uint16
}

// NewQuery returns an initialized Query structure from the given query
// parameters.
func NewQuery(qname string, qtype uint16, qclass uint16) *Query {
	q := new(Query)
	q.Name = dns.Fqdn(qname)
	q.Type = qtype
	q.Class = qclass
	return q
}

// MakeQuery constructs a DNS query message (*dns.Msg) from the given
// query and resolver parameters.
func makeQueryMessage(query *Query, resolver *Resolver) *dns.Msg {

	m := new(dns.Msg)
	m.Id = dns.Id()
	m.RecursionDesired = resolver.Rdflag
	m.AuthenticatedData = resolver.Adflag
	m.CheckingDisabled = resolver.Cdflag
	m.SetEdns0(resolver.Payload, true)
	m.Question = make([]dns.Question, 1)
	m.Question[0] = dns.Question{Name: query.Name, Qtype: query.Type,
		Qclass: query.Class}
	return m
}

// SendQueryUDP sends a DNS query via UDP with timeout and retries if
// necessary.
func sendQueryUDP(query *Query, resolver *Resolver) (*dns.Msg, error) {

	var response *dns.Msg
	var err error

	m := makeQueryMessage(query, resolver)

	c := new(dns.Client)
	c.Net = "udp"
	c.Timeout = resolver.Timeout

	retries := resolver.Retries
	for retries > 0 {
		for _, server := range resolver.Servers {
			response, _, err = c.Exchange(m, server.Address())
			if err == nil {
				return response, err
			}
			if nerr, ok := err.(net.Error); ok && !nerr.Timeout() {
				continue
			}
		}
		retries--
	}

	return nil, err
}

// SendQueryTCP sends a DNS query via TCP.
func sendQueryTCP(query *Query, resolver *Resolver) (*dns.Msg, error) {

	var response *dns.Msg
	var err error

	m := makeQueryMessage(query, resolver)

	c := new(dns.Client)
	c.Net = "tcp"
	c.Timeout = resolver.Timeout

	for _, server := range resolver.Servers {
		response, _, err = c.Exchange(m, server.Address())
		if err == nil {
			return response, err
		}
	}
	return response, err

}

// SendQuery sends a DNS query via UDP with fallback to TCP upon truncation.
func sendQuery(query *Query, resolver *Resolver) (*dns.Msg, error) {

	var response *dns.Msg
	var err error

	response, err = sendQueryUDP(query, resolver)

	if err == nil && response.MsgHdr.Truncated {
		response, err = sendQueryTCP(query, resolver)
	}

	if err != nil {
		return nil, err
	}
	if response == nil {
		return nil, errors.New("null response to DNS query")
	}
	return response, err
}

// responseOK determines whether we have an authoritative response in
// the given DNS message (NOERROR or NXDOMAIN).
func responseOK(response *dns.Msg) bool {

	switch response.MsgHdr.Rcode {
	case dns.RcodeSuccess, dns.RcodeNameError:
		return true
	default:
		return false
	}
}

// GetAddresses obtains a list of IPv4 and IPv6 addresses for given hostname.
func GetAddresses(resolver *Resolver, hostname string, secure bool) ([]net.IP, error) {

	var ipList []net.IP
	var q *Query
	var rrTypes []uint16

	if resolver.IPv6 {
		rrTypes = append(rrTypes, dns.TypeAAAA)
	}
	if resolver.IPv4 {
		rrTypes = append(rrTypes, dns.TypeA)
	}

	for _, rrtype := range rrTypes {
		q = NewQuery(hostname, rrtype, dns.ClassINET)
		response, err := sendQuery(q, resolver)
		if err != nil {
			return nil, err
		}
		if !responseOK(response) {
			return nil, fmt.Errorf("address lookup for %s failed, rcode %d",
				hostname, response.MsgHdr.Rcode)
		}
		if response.MsgHdr.Rcode == dns.RcodeNameError {
			return nil, fmt.Errorf("%s: non-existent domain name", hostname)
		}
		if secure && !response.MsgHdr.AuthenticatedData {
			return nil, fmt.Errorf("%s address response was not authenticated", hostname)
		}

		for _, rr := range response.Answer {
			if rr.Header().Rrtype == rrtype {
				if rrtype == dns.TypeAAAA {
					ipList = append(ipList, rr.(*dns.AAAA).AAAA)
				} else if rrtype == dns.TypeA {
					ipList = append(ipList, rr.(*dns.A).A)
				}
			}
		}
	}

	return ipList, nil
}

// Message2TSLAinfo returns a populated TLSAinfo structure from the
// contents of a given dns message that contains a response to a
// TLSA query. The qname parameter provides the expected TLSA query
// name string.
func Message2TSLAinfo(qname string, message *dns.Msg) *TLSAinfo {

	var tr *TLSArdata

	tlsa := new(TLSAinfo)
	tlsa.Qname = dns.Fqdn(qname)

	for _, rr := range message.Answer {
		if tlsarr, ok := rr.(*dns.TLSA); ok {
			if tlsarr.Hdr.Name != tlsa.Qname {
				tlsa.Alias = append(tlsa.Alias, tlsarr.Hdr.Name)
			}
			tr = new(TLSArdata)
			tr.Usage = tlsarr.Usage
			tr.Selector = tlsarr.Selector
			tr.Mtype = tlsarr.MatchingType
			tr.Data = tlsarr.Certificate
			tlsa.Rdata = append(tlsa.Rdata, tr)
		}
	}
	return tlsa
}

// GetTLSA returns the DNS TLSA RRset information for the given hostname,
// port and resolver parameters.
func GetTLSA(resolver *Resolver, hostname string, port int) (*TLSAinfo, error) {

	var q *Query

	qname := fmt.Sprintf("_%d._tcp.%s", port, hostname)

	q = NewQuery(qname, dns.TypeTLSA, dns.ClassINET)
	response, err := sendQuery(q, resolver)

	if err != nil {
		return nil, err
	}

	if !responseOK(response) {
		return nil, fmt.Errorf("bad response code to TLSA query %s: %s", qname,
			dns.RcodeToString[response.MsgHdr.Rcode])
	}

	if !response.MsgHdr.AuthenticatedData {
		if resolver.Pkixfallback {
			return nil, nil
		}
		return nil, fmt.Errorf("response unauthenticated: %s/TLSA", qname)
	}

	if response.MsgHdr.Rcode == dns.RcodeNameError {
		if resolver.Pkixfallback {
			return nil, nil
		}
		return nil, fmt.Errorf("%s: non-existent domain name", hostname)
	}

	tlsa := Message2TSLAinfo(q.Name, response)

	if len(tlsa.Rdata) == 0 {
		if resolver.Pkixfallback {
			return nil, nil
		}
		return nil, fmt.Errorf("no TLSA records found: %s", qname)
	}

	return tlsa, err
}
