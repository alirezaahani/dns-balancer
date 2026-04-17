package main

import (
	"net"
	"strings"
	"sync/atomic"

	"github.com/miekg/dns"
)

type CustomRule struct {
	Domains []string // suffix match
	IPs     []net.IP // multiple IPs (round robin)
	rrIndex uint64   // atomic counter
}

type CustomResolver struct {
	rules []CustomRule
}

func NewCustomResolver(rules []CustomRule) *CustomResolver {
	for i := range rules {
		for j := range rules[i].Domains {
			rules[i].Domains[j] = dns.Fqdn(strings.ToLower(rules[i].Domains[j]))
		}
	}
	return &CustomResolver{rules: rules}
}

func (c *CustomResolver) Resolve(query []byte) ([]byte, bool) {
	msg := new(dns.Msg)
	if err := msg.Unpack(query); err != nil || len(msg.Question) == 0 {
		return nil, false
	}

	q := msg.Question[0]
	name := strings.ToLower(q.Name)

	if q.Qtype != dns.TypeA {
		return nil, false
	}

	for i := range c.rules {
		rule := &c.rules[i]

		for _, domain := range rule.Domains {
			if strings.HasSuffix(name, domain) {
				return c.buildResponse(msg, rule), true
			}
		}
	}

	return nil, false
}

// buildResponse creates a DNS response with round-robin IP selection
func (c *CustomResolver) buildResponse(req *dns.Msg, rule *CustomRule) []byte {
	resp := new(dns.Msg)
	resp.SetReply(req)
	resp.Authoritative = true

	// Round-robin selection
	idx := atomic.AddUint64(&rule.rrIndex, 1)
	ip := rule.IPs[idx%uint64(len(rule.IPs))]

	rr := &dns.A{
		Hdr: dns.RR_Header{
			Name:   req.Question[0].Name,
			Rrtype: dns.TypeA,
			Class:  dns.ClassINET,
			Ttl:    60, // TODO: configurable
		},
		A: ip,
	}

	resp.Answer = []dns.RR{rr}

	buf, _ := resp.Pack()
	return buf
}
