package dane

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/shuque/dane/v2/danetest"
)

func rr(t *testing.T, s string) dns.RR {
	t.Helper()
	r, err := dns.NewRR(s)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func lookup(t *testing.T, srv *danetest.DNSServer, name string) (*RRset, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	r := NewResolver(srv.Addr)
	return r.LookupTLSA(ctx, name)
}

const soa = "example. 600 IN SOA ns.example. h.example. 1 2 3 4 60"

func TestLookupSuccess(t *testing.T) {
	srv := danetest.NewDNSServer(t)
	srv.Set("a.example.", dns.TypeTLSA, danetest.Answer{AD: true, Answer: []dns.RR{
		rr(t, "a.example. 300 IN TLSA 3 1 1 aabbcc"),
		rr(t, "a.example. 100 IN TLSA 3 1 1 ddeeff"),
	}})
	set, err := lookup(t, srv, "A.example")
	if err != nil {
		t.Fatal(err)
	}
	if len(set.Records) != 2 || set.TTL != 100 || set.Owner != set.Qname || set.Qname != "a.example." {
		t.Fatalf("%+v", set)
	}
	if len(set.Records[0].Data) != 3 {
		t.Fatalf("data %x", set.Records[0].Data)
	}
}

func TestLookupCNAMEChain(t *testing.T) {
	srv := danetest.NewDNSServer(t)
	srv.Set("a.", dns.TypeTLSA, danetest.Answer{AD: true, Answer: []dns.RR{
		rr(t, "a. 200 IN CNAME b."),
		rr(t, "B. 50 IN CNAME c."),
		rr(t, "c. 300 IN TLSA 3 1 1 aabbcc"),
	}})
	set, err := lookup(t, srv, "a.")
	if err != nil {
		t.Fatal(err)
	}
	if set.Owner != "c." || len(set.Aliases) != 2 || set.Aliases[0] != "b." || set.Aliases[1] != "c." || set.TTL != 50 {
		t.Fatalf("%+v", set)
	}
}

func TestLookupIgnoresUnrelatedOwner(t *testing.T) {
	srv := danetest.NewDNSServer(t)
	srv.Set("a.", dns.TypeTLSA, danetest.Answer{AD: true, Answer: []dns.RR{
		rr(t, "x. 300 IN TLSA 3 1 1 aabbcc"),
	}})
	_, err := lookup(t, srv, "a.")
	if !errors.Is(err, ErrNoData) {
		t.Fatal(err)
	}
}

func TestLookupInsecure(t *testing.T) {
	srv := danetest.NewDNSServer(t)
	srv.Set("a.", dns.TypeTLSA, danetest.Answer{Answer: []dns.RR{
		rr(t, "a. 300 IN TLSA 3 1 1 aabbcc"),
	}})
	_, err := lookup(t, srv, "a.")
	if !errors.Is(err, ErrInsecure) {
		t.Fatal(err)
	}
}

func TestLookupInsecureNXDOMAIN(t *testing.T) {
	srv := danetest.NewDNSServer(t)
	srv.Set("a.", dns.TypeTLSA, danetest.Answer{Rcode: dns.RcodeNameError})
	_, err := lookup(t, srv, "a.")
	if !errors.Is(err, ErrInsecure) {
		t.Fatal(err)
	}
}

func TestLookupNXDOMAIN(t *testing.T) {
	srv := danetest.NewDNSServer(t)
	srv.Set("a.example.", dns.TypeTLSA, danetest.Answer{Rcode: dns.RcodeNameError, AD: true, Ns: []dns.RR{rr(t, soa)}})
	_, err := lookup(t, srv, "a.example.")
	if !errors.Is(err, ErrNXDOMAIN) {
		t.Fatal(err)
	}
	var le *LookupError
	if !errors.As(err, &le) || le.NegTTL != 60 || le.Rcode != dns.RcodeNameError {
		t.Fatalf("%+v", le)
	}
}

func TestLookupNoData(t *testing.T) {
	srv := danetest.NewDNSServer(t)
	srv.Set("a.example.", dns.TypeTLSA, danetest.Answer{AD: true, Ns: []dns.RR{rr(t, soa)}})
	_, err := lookup(t, srv, "a.example.")
	var le *LookupError
	if !errors.Is(err, ErrNoData) || !errors.As(err, &le) || le.NegTTL != 60 {
		t.Fatal(err)
	}
}

func TestLookupServFail(t *testing.T) {
	srv := danetest.NewDNSServer(t)
	_, err := lookup(t, srv, "unknown.")
	var le *LookupError
	if !errors.Is(err, ErrServFail) || !errors.As(err, &le) || le.Rcode != 2 {
		t.Fatalf("%v", err)
	}
}

func TestLookupTimeout(t *testing.T) {
	srv := danetest.NewDNSServer(t)
	srv.Set("a.", dns.TypeTLSA, danetest.Answer{AD: true, Delay: time.Second, Answer: []dns.RR{
		rr(t, "a. 300 IN TLSA 3 1 1 aabbcc"),
	}})
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	_, err := NewResolver(srv.Addr).LookupTLSA(ctx, "a.")
	var le *LookupError
	if !errors.Is(err, ErrTimeout) || !errors.As(err, &le) || le.Rcode != -1 {
		t.Fatalf("%v", err)
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("transport error not reachable")
	}
}

func TestLookupWildcardExpanded(t *testing.T) {
	srv := danetest.NewDNSServer(t)
	srv.Set("dev1._device.example.", dns.TypeTLSA, danetest.Answer{AD: true, Answer: []dns.RR{
		rr(t, "dev1._device.example. 300 IN TLSA 3 1 1 aabbcc"),
	}})
	set, err := lookup(t, srv, "dev1._device.example.")
	if err != nil || len(set.Records) != 1 {
		t.Fatal(err)
	}
}

func TestServiceName(t *testing.T) {
	if got := ServiceName(443, "tcp", "Example.com."); got != "_443._tcp.example.com." {
		t.Fatal(got)
	}
}

func TestTLSAFromRRInvalidHex(t *testing.T) {
	for _, h := range []string{"abc", "zz", "aazz"} {
		got := tlsaFromRR(&dns.TLSA{Usage: 3, Selector: 1, MatchingType: 1, Certificate: h})
		if got.Data != nil || got.Usage != 3 {
			t.Fatalf("%q: %+v", h, got)
		}
	}
}

func TestLookupDNAMESynthesized(t *testing.T) {
	srv := danetest.NewDNSServer(t)
	srv.Set("a._device.example.com.", dns.TypeTLSA, danetest.Answer{AD: true, Answer: []dns.RR{
		rr(t, "example.com. 300 IN DNAME example.net."),
		rr(t, "a._device.example.com. 300 IN CNAME a._device.example.net."),
		rr(t, "a._device.example.net. 300 IN TLSA 3 1 1 aabbcc"),
	}})
	set, err := lookup(t, srv, "a._device.example.com.")
	if err != nil {
		t.Fatal(err)
	}
	if set.Owner != "a._device.example.net." || len(set.Aliases) != 1 || len(set.Records) != 1 {
		t.Fatalf("%+v", set)
	}
}

func TestLookupCancelPrompt(t *testing.T) {
	srv := danetest.NewDNSServer(t)
	srv.Set("a.", dns.TypeTLSA, danetest.Answer{AD: true, Drop: true})
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(100*time.Millisecond, cancel)
	start := time.Now()
	_, err := NewResolver(srv.Addr).LookupTLSA(ctx, "a.")
	if d := time.Since(start); d > 500*time.Millisecond {
		t.Fatalf("took %v", d)
	}
	if !errors.Is(err, context.Canceled) || !errors.Is(err, ErrTimeout) {
		t.Fatalf("err = %v", err)
	}
}

func TestLookupCNAMELoop(t *testing.T) {
	srv := danetest.NewDNSServer(t)
	srv.Set("a.", dns.TypeTLSA, danetest.Answer{AD: true, Answer: []dns.RR{
		rr(t, "a. 300 IN CNAME b."),
		rr(t, "b. 300 IN CNAME a."),
	}})
	_, err := lookup(t, srv, "a.")
	if !errors.Is(err, ErrServFail) || errors.Is(err, ErrNoData) {
		t.Fatalf("err = %v", err)
	}
}

func TestLookupCNAMETooLong(t *testing.T) {
	srv := danetest.NewDNSServer(t)
	var ans []dns.RR
	for i := 0; i < 10; i++ {
		ans = append(ans, rr(t, fmt.Sprintf("h%d. 300 IN CNAME h%d.", i, i+1)))
	}
	ans = append(ans, rr(t, "h10. 300 IN TLSA 3 1 1 aabbcc"))
	srv.Set("h0.", dns.TypeTLSA, danetest.Answer{AD: true, Answer: ans})
	_, err := lookup(t, srv, "h0.")
	if !errors.Is(err, ErrServFail) || errors.Is(err, ErrNoData) {
		t.Fatalf("err = %v", err)
	}
}

func TestLookupQuestionMismatch(t *testing.T) {
	srv := danetest.NewDNSServer(t)
	srv.Set("a.", dns.TypeTLSA, danetest.Answer{AD: true, Question: "evil.", Answer: []dns.RR{
		rr(t, "a. 300 IN TLSA 3 1 1 aabbcc"),
	}})
	_, err := lookup(t, srv, "a.")
	if !errors.Is(err, ErrServFail) {
		t.Fatalf("err = %v", err)
	}
}

func TestLookupInsecureNODATA(t *testing.T) {
	srv := danetest.NewDNSServer(t)
	srv.Set("a.example.", dns.TypeTLSA, danetest.Answer{Ns: []dns.RR{rr(t, soa)}})
	_, err := lookup(t, srv, "a.example.")
	if !errors.Is(err, ErrInsecure) || errors.Is(err, ErrNoData) {
		t.Fatalf("err = %v", err)
	}
}

func TestLookupREFUSED(t *testing.T) {
	srv := danetest.NewDNSServer(t)
	srv.Set("a.", dns.TypeTLSA, danetest.Answer{Rcode: dns.RcodeRefused, AD: true})
	_, err := lookup(t, srv, "a.")
	var le *LookupError
	if !errors.Is(err, ErrServFail) || !errors.As(err, &le) || le.Rcode != dns.RcodeRefused {
		t.Fatalf("err = %v", err)
	}
}
