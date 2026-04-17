package main

import (
	"fmt"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
)

type Resolver struct {
	Addr string
}

func (r Resolver) String() string {
	return r.Addr
}

type resolverStats struct {
	sent uint64
	ok   uint64
	fail uint64
}

// ResolverPool manages a set of upstream resolvers with health tracking.
type ResolverPool struct {
	resolvers      []Resolver
	mu             sync.RWMutex
	healthy        map[Resolver]bool
	healthyCache   []Resolver
	stats          map[Resolver]*resolverStats
	failStreak     map[Resolver]int
	rrIndex        uint64
	onResolverDown func()

	testDomain     string
	testIP         net.IP
	failGenerosity int
}

const (
	dnsBufferSize   = 4096
	upstreamTimeout = 1 * time.Second
)

func sendQueryUDP(data []byte, addr string, timeout time.Duration) ([]byte, error) {
	conn, err := net.DialTimeout("udp", addr, timeout)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))
	if _, err := conn.Write(data); err != nil {
		return nil, err
	}
	buf := make([]byte, dnsBufferSize)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, err
	}
	return buf[:n], nil
}

func NewResolverPool(resolvers []Resolver, testDomain string, testIP net.IP, failGenerosity int) *ResolverPool {
	p := &ResolverPool{
		resolvers:    resolvers,
		healthy:      make(map[Resolver]bool, len(resolvers)),
		healthyCache: make([]Resolver, len(resolvers)),
		stats:        make(map[Resolver]*resolverStats, len(resolvers)),
		failStreak:   make(map[Resolver]int, len(resolvers)),
		testDomain:   testDomain,
		testIP:       testIP,
	}
	copy(p.healthyCache, resolvers)
	for _, r := range resolvers {
		p.healthy[r] = true
		p.stats[r] = &resolverStats{}
	}
	return p
}

func (p *ResolverPool) rebuildHealthyCache() {
	cache := make([]Resolver, 0, len(p.resolvers))
	for _, r := range p.resolvers {
		if p.healthy[r] {
			cache = append(cache, r)
		}
	}
	if len(cache) == 0 {
		cache = make([]Resolver, len(p.resolvers))
		copy(cache, p.resolvers)
	}
	p.healthyCache = cache
}

func (p *ResolverPool) GetNext() Resolver {
	p.mu.RLock()
	healthy := p.healthyCache
	p.mu.RUnlock()

	idx := atomic.AddUint64(&p.rrIndex, 1) - 1
	return healthy[idx%uint64(len(healthy))]
}

func (p *ResolverPool) SendQuery(data []byte, r Resolver) ([]byte, error) {
	return sendQueryUDP(data, r.Addr, upstreamTimeout)
}

func (p *ResolverPool) MarkSent(r Resolver) {
	p.mu.RLock()
	s := p.stats[r]
	p.mu.RUnlock()
	atomic.AddUint64(&s.sent, 1)
}

func (p *ResolverPool) MarkSuccess(r Resolver) {
	p.mu.Lock()
	defer p.mu.Unlock()
	s := p.stats[r]
	atomic.AddUint64(&s.ok, 1)
	p.failStreak[r] = 0
	if !p.healthy[r] {
		p.healthy[r] = true
		p.rebuildHealthyCache()
	}
}

func (p *ResolverPool) MarkFailure(r Resolver) {
	p.mu.Lock()
	s := p.stats[r]
	atomic.AddUint64(&s.fail, 1)
	p.failStreak[r]++
	// Generous threshold: during internet shutdowns DNS servers fail temporarily
	// but may come back, so we allow many consecutive failures before marking down.
	var cb func()
	if p.failStreak[r] >= p.failGenerosity && p.healthy[r] {
		p.healthy[r] = false
		p.rebuildHealthyCache()
		cb = p.onResolverDown
		slog.Warn("Resolver marked unhealthy", "resolver", r, "streak", p.failStreak[r])
	}
	p.mu.Unlock()
	if cb != nil {
		go cb()
	}
}

func (p *ResolverPool) SetOnResolverDown(fn func()) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.onResolverDown = fn
}

func (p *ResolverPool) IsHealthy(raw []byte) bool {
	msg := new(dns.Msg)
	if err := msg.Unpack(raw); err != nil {
		return false
	}

	if len(msg.Answer) == 0 {
		return false
	}

	for _, ans := range msg.Answer {
		if ans, ok := ans.(*dns.A); ok {
			ip := ans.A
			if p.testIP.Equal(ip) {
				return true
			}
		}
	}

	return false
}

func (p *ResolverPool) HealthCheck() {
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(p.testDomain), dns.TypeA)
	msg.RecursionDesired = true

	query, err := msg.Pack()
	if err != nil {
		return
	}

	type result struct {
		r     Resolver
		alive bool
	}

	ch := make(chan result, len(p.resolvers))
	for _, r := range p.resolvers {
		go func(r Resolver) {
			raw, err := p.SendQuery(query, r)
			ch <- result{r, (err == nil) && p.IsHealthy(raw)}
		}(r)
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	for range p.resolvers {
		res := <-ch
		p.healthy[res.r] = res.alive
		if res.alive {
			p.failStreak[res.r] = 0
		}
	}
	p.rebuildHealthyCache()
}

func (p *ResolverPool) HealthyCount() int {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return len(p.healthyCache)
}

func (p *ResolverPool) StatsString() string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	var result string
	for _, r := range p.resolvers {
		if !p.healthy[r] {
			continue
		}
		s := p.stats[r]
		result += fmt.Sprintf("  %40s sent=%-6d ok=%-6d fail=%d\n",
			r.String(),
			atomic.LoadUint64(&s.sent),
			atomic.LoadUint64(&s.ok),
			atomic.LoadUint64(&s.fail))
	}
	return result
}

const (
	HealthCheckInterval = 30 * time.Second
	StatsInterval       = 60 * time.Second
)
