package dane

import (
	"context"
	"errors"
	"net"
	"reflect"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/shuque/dane/v2/danetest"
)

func tlsaRR(t *testing.T) dns.RR {
	t.Helper()
	rr, err := dns.NewRR("a.example. 300 IN TLSA 3 1 1 " +
		"0000000000000000000000000000000000000000000000000000000000000000")
	if err != nil {
		t.Fatal(err)
	}
	return rr
}

func TestExchangeBasic(t *testing.T) {
	s := danetest.NewDNSServer(t)
	s.Set("a.example.", dns.TypeTLSA, danetest.Answer{AD: true, Answer: []dns.RR{tlsaRR(t)}})
	r := NewResolver(s.Addr)
	m, err := r.Exchange(context.Background(), "a.example.", dns.TypeTLSA)
	if err != nil {
		t.Fatal(err)
	}
	if !m.AuthenticatedData || len(m.Answer) != 1 {
		t.Fatalf("AD=%v answers=%d", m.AuthenticatedData, len(m.Answer))
	}
	q := s.LastQuery()
	if q == nil {
		t.Fatal("server saw no query")
	}
	if !q.AuthenticatedData {
		t.Error("query lacked AD bit")
	}
	if !q.RecursionDesired {
		t.Error("query lacked RD bit")
	}
	opt := q.IsEdns0()
	if opt == nil || !opt.Do() {
		t.Error("query lacked EDNS0 DO")
	} else if opt.UDPSize() != 1232 {
		t.Errorf("payload %d", opt.UDPSize())
	}
}

func TestExchangeTCPFallback(t *testing.T) {
	s := danetest.NewDNSServer(t)
	s.Set("a.example.", dns.TypeTLSA, danetest.Answer{AD: true, Truncate: true, Answer: []dns.RR{tlsaRR(t)}})
	r := NewResolver(s.Addr)
	m, err := r.Exchange(context.Background(), "a.example.", dns.TypeTLSA)
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Answer) != 1 {
		t.Fatalf("answers=%d", len(m.Answer))
	}
	if n := s.Queries(); n != 2 {
		t.Errorf("Queries=%d, want 2", n)
	}
}

func TestExchangeTimeout(t *testing.T) {
	s := danetest.NewDNSServer(t)
	s.Set("a.example.", dns.TypeTLSA, danetest.Answer{Delay: 2 * time.Second, Answer: []dns.RR{tlsaRR(t)}})
	r := NewResolver(s.Addr)
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := r.Exchange(ctx, "a.example.", dns.TypeTLSA)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v", err)
	}
	if d := time.Since(start); d > time.Second {
		t.Errorf("took %v", d)
	}
}

func TestNewResolverDefaults(t *testing.T) {
	r := NewResolver("127.0.0.1")
	if !reflect.DeepEqual(r.Servers, []string{"127.0.0.1:53"}) {
		t.Errorf("%v", r.Servers)
	}
	if r.Timeout != 2*time.Second || r.Retries != 3 || r.Payload != 1232 {
		t.Errorf("defaults %+v", r)
	}
	r = NewResolver("::1")
	if !reflect.DeepEqual(r.Servers, []string{"[::1]:53"}) {
		t.Errorf("%v", r.Servers)
	}
}

func TestResolverFailover(t *testing.T) {
	// A port with nothing listening (UDP gets ICMP refused, TCP gets RST).
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	dead := ln.Addr().String()
	ln.Close()

	s := danetest.NewDNSServer(t)
	s.Set("a.example.", dns.TypeTLSA, danetest.Answer{AD: true, Answer: []dns.RR{tlsaRR(t)}})
	r := NewResolver(dead, s.Addr)
	r.Retries = 1
	r.Timeout = 500 * time.Millisecond
	m, err := r.Exchange(context.Background(), "a.example.", dns.TypeTLSA)
	if err != nil || len(m.Answer) != 1 {
		t.Fatalf("m=%v err=%v", m, err)
	}
}
