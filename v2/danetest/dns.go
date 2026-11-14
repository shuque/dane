package danetest

import (
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// Answer describes the canned response for one (name, type).
type Answer struct {
	Rcode    int // dns.RcodeSuccess etc.
	AD       bool
	Answer   []dns.RR
	Ns       []dns.RR
	Delay    time.Duration
	Truncate bool // UDP response has TC=1 with no answers; TCP gets the full answer
}

type key struct {
	name  string
	qtype uint16
}

// DNSServer is an in-process UDP+TCP fake DNS server.
type DNSServer struct {
	Addr string // "127.0.0.1:port"

	mu      sync.Mutex
	answers map[key]Answer
	queries int
	last    *dns.Msg
	done    chan struct{}
}

func canon(name string) string { return strings.ToLower(dns.Fqdn(name)) }

// NewDNSServer starts a server on 127.0.0.1 (same port for UDP and
// TCP) and shuts it down via t.Cleanup. Unknown names get SERVFAIL.
func NewDNSServer(t testing.TB) *DNSServer {
	t.Helper()
	s := &DNSServer{answers: map[key]Answer{}, done: make(chan struct{})}

	var pc net.PacketConn
	var ln net.Listener
	for i := 0; i < 20; i++ {
		var err error
		pc, err = net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		ln, err = net.Listen("tcp", pc.LocalAddr().String())
		if err == nil {
			break
		}
		pc.Close()
		pc, ln = nil, nil
	}
	if pc == nil {
		t.Fatal("danetest: could not bind UDP and TCP to the same port")
	}
	s.Addr = pc.LocalAddr().String()

	var wg sync.WaitGroup
	var servers []*dns.Server
	for _, srv := range []*dns.Server{
		{PacketConn: pc, Handler: dns.HandlerFunc(s.handle)},
		{Listener: ln, Handler: dns.HandlerFunc(s.handle)},
	} {
		started := make(chan struct{})
		srv.NotifyStartedFunc = func() { close(started) }
		servers = append(servers, srv)
		wg.Add(1)
		go func() {
			defer wg.Done()
			srv.ActivateAndServe()
		}()
		<-started
	}
	t.Cleanup(func() {
		close(s.done) // wake any delayed handlers
		for _, srv := range servers {
			srv.Shutdown()
		}
		wg.Wait()
	})
	return s
}

// Set installs the answer for qname (case-insensitive, FQDN or not) and qtype.
func (s *DNSServer) Set(qname string, qtype uint16, a Answer) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.answers[key{canon(qname), qtype}] = a
}

// Queries returns the total number of queries received (UDP+TCP).
func (s *DNSServer) Queries() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.queries
}

// LastQuery returns a copy of the most recent query, or nil if none.
func (s *DNSServer) LastQuery() *dns.Msg {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.last == nil {
		return nil
	}
	return s.last.Copy()
}

func (s *DNSServer) handle(w dns.ResponseWriter, req *dns.Msg) {
	resp := new(dns.Msg)
	resp.SetReply(req)
	resp.RecursionAvailable = true

	var a Answer
	found := false
	s.mu.Lock()
	s.queries++
	s.last = req.Copy()
	if len(req.Question) == 1 {
		a, found = s.answers[key{canon(req.Question[0].Name), req.Question[0].Qtype}]
	}
	s.mu.Unlock()

	if !found {
		resp.Rcode = dns.RcodeServerFailure
		w.WriteMsg(resp)
		return
	}
	if a.Delay > 0 {
		select {
		case <-time.After(a.Delay):
		case <-s.done:
			return
		}
	}
	_, isTCP := w.RemoteAddr().(*net.TCPAddr)
	resp.Rcode = a.Rcode
	resp.AuthenticatedData = a.AD
	if a.Truncate && !isTCP {
		resp.Truncated = true
	} else {
		resp.Answer = a.Answer
		resp.Ns = a.Ns
	}
	w.WriteMsg(resp)
}
