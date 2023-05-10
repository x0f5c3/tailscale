// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package recursive implements a simple recursive DNS resolver.
package recursive

import (
	"context"
	"fmt"
	"net"
	"net/netip"

	"github.com/miekg/dns"
	"golang.org/x/exp/maps"
	"golang.org/x/exp/slices"
	"tailscale.com/envknob"
	"tailscale.com/net/netns"
	"tailscale.com/types/logger"
	"tailscale.com/util/mak"
	"tailscale.com/util/multierr"
	"tailscale.com/util/slicesx"
)

const maxDepth = 10

var errMaxDepth = fmt.Errorf("exceeded max depth %d when resolving", maxDepth)

var rootServersV4 = []netip.Addr{
	netip.MustParseAddr("198.41.0.4"),     // a.root-servers.net
	netip.MustParseAddr("199.9.14.201"),   // b.root-servers.net
	netip.MustParseAddr("192.33.4.12"),    // c.root-servers.net
	netip.MustParseAddr("199.7.91.13"),    // d.root-servers.net
	netip.MustParseAddr("192.203.230.10"), // e.root-servers.net
	netip.MustParseAddr("192.5.5.241"),    // f.root-servers.net
	netip.MustParseAddr("192.112.36.4"),   // g.root-servers.net
	netip.MustParseAddr("198.97.190.53"),  // h.root-servers.net
	netip.MustParseAddr("192.36.148.17"),  // i.root-servers.net
	netip.MustParseAddr("192.58.128.30"),  // j.root-servers.net
	netip.MustParseAddr("193.0.14.129"),   // k.root-servers.net
	netip.MustParseAddr("199.7.83.42"),    // l.root-servers.net
	netip.MustParseAddr("202.12.27.33"),   // m.root-servers.net
}

var rootServersV6 = []netip.Addr{
	netip.MustParseAddr("2001:503:ba3e::2:30"), // a.root-servers.net
	netip.MustParseAddr("2001:500:200::b"),     // b.root-servers.net
	netip.MustParseAddr("2001:500:2::c"),       // c.root-servers.net
	netip.MustParseAddr("2001:500:2d::d"),      // d.root-servers.net
	netip.MustParseAddr("2001:500:a8::e"),      // e.root-servers.net
	netip.MustParseAddr("2001:500:2f::f"),      // f.root-servers.net
	netip.MustParseAddr("2001:500:12::d0d"),    // g.root-servers.net
	netip.MustParseAddr("2001:500:1::53"),      // h.root-servers.net
	netip.MustParseAddr("2001:7fe::53"),        // i.root-servers.net
	netip.MustParseAddr("2001:503:c27::2:30"),  // j.root-servers.net
	netip.MustParseAddr("2001:7fd::1"),         // k.root-servers.net
	netip.MustParseAddr("2001:500:9f::42"),     // l.root-servers.net
	netip.MustParseAddr("2001:dc3::35"),        // m.root-servers.net
}

var debug = envknob.RegisterBool("TS_DEBUG_RECURSIVE_DNS")

// Resolver is a recursive DNS resolver that is designed for looking up A and AAAA records.
type Resolver struct {
	// Dialer is used to create outbound connections. If nil, a zero
	// net.Dialer will be used instead.
	Dialer netns.Dialer

	// Logf is the logging function to use; if none is specified, then logs
	// will be dropped.
	Logf logger.Logf

	// NoIPv6, if set, will prevent this package from querying for AAAA
	// records and will avoid contacting nameservers over IPv6.
	NoIPv6 bool

	// Possible future additions:
	//    - Additional nameservers? From the system maybe?
	//    - NoIPv4 for IPv4
	//    - DNS-over-HTTPS or DNS-over-TLS support
}

func (r *Resolver) logf(format string, args ...any) {
	if r.Logf == nil {
		return
	}
	r.Logf(format, args...)
}

func (r *Resolver) dlogf(format string, args ...any) {
	if r.Logf == nil || !debug() {
		return
	}
	r.Logf(format, args...)
}

func (r *Resolver) dialer() netns.Dialer {
	if r.Dialer != nil {
		return r.Dialer
	}

	return &net.Dialer{}
}

// Resolve will perform a recursive DNS resolution for the provided name,
// starting at a randomly-chosen root DNS server, and return the A and AAAA
// responses as a slice of netip.Addrs.
func (r *Resolver) Resolve(ctx context.Context, name string) ([]netip.Addr, error) {
	// Select 3 random root nameservers to start from, since if we don't
	// get responses from those, something else has probably gone horribly
	// wrong.
	roots4 := slices.Clone(rootServersV4)
	slicesx.Shuffle(roots4)
	roots4 = roots4[:3]

	var roots6 []netip.Addr
	if !r.NoIPv6 {
		roots6 = slices.Clone(rootServersV6)
		slicesx.Shuffle(roots6)
		roots6 = roots6[:3]
	}

	// Interleave the root servers so that we try to contact them over
	// IPv4, then IPv6, IPv4, IPv6, etc.
	rootServers := slicesx.Interleave(roots4, roots6)

	// We want to query using the cross product of the following
	// parameters, to ensure that we're trying every possible option to
	// obtain an answer:
	//   - IPv4 and IPv6 questions/answers (i.e. "the returned IP")
	//   - IPv4 and IPv6 connections to the DNS servers
	//   - TCP and UDP connections
	//
	// We create a candidates list per address family we're querying (i.e.
	// one for A records and one for AAAA records) that we iterate through
	// to make progress.
	//
	// This is a stack, and we ensure that the last candidate in the stack
	// (and thus first attempt) is UDP since a DNS query via UDP doesn't
	// require the TCP 3-way handshake.
	var candidatesA, candidatesAAAA stack[candidateWithDepth]
	for _, ip := range rootServers {
		candidatesA.Push(
			candidateWithDepth{
				candidate: candidate{
					nameserver:   ip,
					protocol:     "tcp",
					questionType: dns.TypeA,
				},
				depth: 0,
			},
			candidateWithDepth{
				candidate: candidate{
					nameserver:   ip,
					protocol:     "udp",
					questionType: dns.TypeA,
				},
				depth: 0,
			},
		)
		if !r.NoIPv6 {
			candidatesAAAA.Push(
				candidateWithDepth{
					candidate: candidate{
						nameserver:   ip,
						protocol:     "tcp",
						questionType: dns.TypeAAAA,
					},
					depth: 0,
				},
				candidateWithDepth{
					candidate: candidate{
						nameserver:   ip,
						protocol:     "udp",
						questionType: dns.TypeAAAA,
					},
					depth: 0,
				},
			)
		}
	}

	// For each loop iteration below, we always want to progress on both v4
	// and v6 candidates to maximize the likelihood that we'll get both an
	// IPv4 and IPv6 result and then be able to finish early before
	// querying all nameservers. Create a list of our candidate stacks that
	// we can then iterate over.
	stacks := []*stack[candidateWithDepth]{&candidatesA, &candidatesAAAA}

	dialer := r.dialer()

	var (
		answers      map[netip.Addr]bool
		queried      map[candidate]bool
		hasV4, hasV6 bool
		errs         []error
	)
	for {
		if candidatesA.Len() == 0 && candidatesAAAA.Len() == 0 {
			break
		}

		// TODO(andrew): is this the right heuristic?
		if len(answers) > 0 && hasV4 && (hasV6 || r.NoIPv6) {
			break
		}

		for _, stack := range stacks {
			// Pull the first candidate off the stack.
			curr, ok := stack.TryPop()
			if !ok {
				continue
			}
			if !curr.nameserver.IsValid() {
				r.logf("unexpected invalid nameserver address")
				continue
			}
			if queried[curr.candidate] {
				r.dlogf("already queried candidate: %v", curr.candidate)
				continue
			}
			mak.Set(&queried, curr.candidate, true)

			currAnswers, currCandidates, err := r.step(ctx, dialer, name, curr)
			if err != nil {
				errs = append(errs, err)
				continue
			}

			// Store answers
			for _, answer := range currAnswers {
				hasV4 = hasV4 || answer.Is4()
				hasV6 = hasV6 || answer.Is6()
				mak.Set(&answers, answer, true)
			}

			// We want to progress further "down" the tree of
			// nameservers, so we push our candidates onto the
			// stack at the end so that we'll pop them on the next
			// loop iteration.
			stack.Push(currCandidates...)
		}
	}

	// If we have any results, then we're good; return them.
	if len(answers) > 0 {
		addrs := maps.Keys(answers)
		slicesx.Shuffle(addrs)
		return addrs, nil
	}

	return nil, multierr.New(errs...)
}

type candidate struct {
	nameserver   netip.Addr // nameserver to query; can be IPv4 or IPv6
	protocol     string     // "udp" or "tcp"
	questionType uint16     // DNS question type
}

func (c candidate) String() string {
	return fmt.Sprintf("%v(proto=%s)(ty=%d)", c.nameserver, c.protocol, c.questionType)
}

type candidateWithDepth struct {
	candidate
	depth int // how far we've recursed
}

func (c candidateWithDepth) String() string {
	return fmt.Sprintf("%v(depth=%d)", c.candidate, c.depth)
}

func (r *Resolver) step(ctx context.Context, dialer netns.Dialer, name string, curr candidateWithDepth) (results []netip.Addr, candidates []candidateWithDepth, err error) {
	// Connect to the nameserver, forcing the correct connection type.
	var network string
	if curr.nameserver.Is4() {
		network = curr.protocol + "4"
	} else {
		network = curr.protocol + "6"
	}

	// Dial the current nameserver using our dialer.
	nameserverStr := curr.nameserver.String()
	nconn, err := dialer.DialContext(ctx, network, nameserverStr+":53")
	if err != nil {
		return nil, nil, err
	}

	var c dns.Client
	conn := &dns.Conn{
		Conn:    nconn,
		UDPSize: c.UDPSize,
	}

	// Prepare a message asking for an appropriately-typed record
	// for the name we're querying.
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), curr.questionType)

	// Send the DNS request to the current nameserver.
	//
	// TODO(andrew): use ExchangeWithConnContext after this upstream PR is
	// merged:
	//    https://github.com/miekg/dns/pull/1459
	r.dlogf("asking %s over %s about %s (type: %v)", nameserverStr, curr.protocol, name, curr.questionType)
	resp, _, err := c.ExchangeWithConn(m, conn)
	if err != nil {
		return nil, nil, err
	}

	// If we get an answer, trust it and we're done.
	if len(resp.Answer) > 0 {
		// Extract and handle the answers; no more processing needed.
		var answers []netip.Addr
		for _, rr := range resp.Answer {
			answer, ok := extractAddr(r.logf, rr)
			if !ok {
				continue
			}
			answers = append(answers, answer)
		}
		return answers, nil, nil
	}

	// Store additional candidates if we're not past our maximum depth.
	if curr.depth == maxDepth {
		r.dlogf("not recursing past maximum depth")
		return nil, nil, errMaxDepth
	}

	for _, rr := range resp.Extra {
		addr, ok := extractAddr(r.logf, rr)
		if !ok {
			continue
		}
		candidates = append(candidates, candidateWithDepth{
			candidate: candidate{
				nameserver:   addr,
				protocol:     curr.protocol,
				questionType: curr.questionType,
			},
			depth: curr.depth + 1,
		})
	}
	return nil, candidates, nil
}

func extractAddr(logf logger.Logf, record dns.RR) (netip.Addr, bool) {
	switch v := record.(type) {
	case *dns.A:
		ip, ok := netip.AddrFromSlice(v.A)
		if !ok || !ip.Is4() {
			logf("unexpected bad IPv4 addr")
			return netip.Addr{}, false
		}
		return ip, true
	case *dns.AAAA:
		ip, ok := netip.AddrFromSlice(v.AAAA)
		if !ok || !ip.Is6() {
			logf("unexpected bad IPv6 addr")
			return netip.Addr{}, false
		}
		return ip, true
	default:
		return netip.Addr{}, false
	}
}

type stack[T any] struct {
	ss []T
}

func (s *stack[T]) Push(items ...T) {
	s.ss = append(s.ss, items...)
}

func (s *stack[T]) Pop() T {
	curr := s.ss[len(s.ss)-1]
	s.ss = s.ss[:len(s.ss)-1]
	return curr
}

func (s *stack[T]) Len() int {
	return len(s.ss)
}

func (s *stack[T]) TryPop() (T, bool) {
	if len(s.ss) == 0 {
		var zero T
		return zero, false
	}
	return s.Pop(), true
}
