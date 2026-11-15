package dane

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/miekg/dns"
)

// Resolver sends DNS queries to a validating recursive resolver and
// relies on its AD bit for DNSSEC authentication.
type Resolver struct {
	Servers []string      // "host:port"; IPv6 in brackets
	Timeout time.Duration // per attempt (UDP and any TCP retry share it); default 2s
	Retries int           // attempts per server; default 3
	Payload uint16        // EDNS0 UDP size; default 1232
}

// NewResolver returns a Resolver with defaults applied. Servers
// lacking a port get ":53".
func NewResolver(servers ...string) *Resolver {
	r := &Resolver{Timeout: 2 * time.Second, Retries: 3, Payload: 1232}
	for _, s := range servers {
		if _, _, err := net.SplitHostPort(s); err != nil {
			s = net.JoinHostPort(trimBrackets(s), "53")
		}
		r.Servers = append(r.Servers, s)
	}
	return r
}

func trimBrackets(s string) string {
	if len(s) > 1 && s[0] == '[' && s[len(s)-1] == ']' {
		return s[1 : len(s)-1]
	}
	return s
}

// ResolverFromConf builds a Resolver from a resolv.conf file
// ("" means /etc/resolv.conf). miekg/dns's parser supplies its own
// timeout and attempts (5s and 2) when the file has no "options"
// line, so the NewResolver defaults do not apply in that case.
func ResolverFromConf(path string) (*Resolver, error) {
	if path == "" {
		path = "/etc/resolv.conf"
	}
	conf, err := dns.ClientConfigFromFile(path)
	if err != nil {
		return nil, err
	}
	if len(conf.Servers) == 0 {
		return nil, fmt.Errorf("dane: no nameservers in %s", path)
	}
	servers := make([]string, len(conf.Servers))
	for i, s := range conf.Servers {
		servers[i] = net.JoinHostPort(s, conf.Port)
	}
	r := NewResolver(servers...)
	if conf.Timeout > 0 {
		r.Timeout = time.Duration(conf.Timeout) * time.Second
	}
	if conf.Attempts > 0 {
		r.Retries = conf.Attempts
	}
	return r, nil
}

// Exchange queries for qname/qtype with RD, AD and EDNS0 DO set. It
// tries each server in order (up to Retries attempts each) over UDP,
// falling back to TCP on truncation, and returns the first response
// regardless of rcode. Transport errors are wrapped with %w so that
// context and net.Error timeouts remain detectable.
func (r *Resolver) Exchange(ctx context.Context, qname string, qtype uint16) (*dns.Msg, error) {
	if len(r.Servers) == 0 {
		return nil, errors.New("dane: resolver has no servers")
	}
	timeout, retries, payload := r.Timeout, r.Retries, r.Payload
	if timeout <= 0 {
		timeout = 2 * time.Second
	}
	if retries <= 0 {
		retries = 3
	}
	if payload == 0 {
		payload = 1232
	}

	q := new(dns.Msg)
	q.SetQuestion(dns.Fqdn(qname), qtype)
	q.RecursionDesired = true
	q.AuthenticatedData = true
	q.SetEdns0(payload, true)

	var lastErr error
	for _, server := range r.Servers {
		for attempt := 0; attempt < retries; attempt++ {
			if err := ctx.Err(); err != nil {
				return nil, ctxErr(err, lastErr)
			}
			resp, err := r.attempt(ctx, q, server, timeout, payload)
			if err == nil {
				return resp, nil
			}
			lastErr = fmt.Errorf("query %s to %s: %w", qname, server, err)
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, ctxErr(err, lastErr)
	}
	return nil, lastErr
}

func ctxErr(ctxErr, last error) error {
	if last == nil {
		return ctxErr
	}
	return fmt.Errorf("%w: %w", ctxErr, last)
}

// attempt performs one UDP exchange (with TCP fallback on truncation).
// It dials explicitly and arms a deadline on cancellation, because
// miekg/dns ExchangeContext honours only context deadlines, not
// cancellation.
func (r *Resolver) attempt(ctx context.Context, q *dns.Msg, server string, timeout time.Duration, payload uint16) (*dns.Msg, error) {
	actx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	q = q.Copy()
	q.Id = dns.Id()
	resp, err := exchangeOnce(actx, &dns.Client{Net: "udp", Timeout: timeout, UDPSize: payload}, q, server)
	if err != nil {
		return nil, err
	}
	if resp.Truncated {
		return exchangeOnce(actx, &dns.Client{Net: "tcp", Timeout: timeout}, q, server)
	}
	return resp, nil
}

func exchangeOnce(ctx context.Context, c *dns.Client, q *dns.Msg, server string) (*dns.Msg, error) {
	co, err := c.DialContext(ctx, server)
	if err != nil {
		return nil, err
	}
	defer co.Close()
	stop := context.AfterFunc(ctx, func() { co.SetDeadline(time.Unix(1, 0)) })
	defer stop()
	resp, _, err := c.ExchangeWithConnContext(ctx, q, co)
	if err != nil && ctx.Err() != nil {
		err = fmt.Errorf("%w: %w", ctx.Err(), err)
	}
	return resp, err
}
