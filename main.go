package main

import (
	"bufio"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

func main() {
	var (
		listenAddr     string
		listenPath     string
		resolverFile   string
		rulesFile      string
		certFile       string
		keyFile        string
		testDomain     string
		testIPStr      string
		cacheSize      int
		showStats      bool
		failGenerosity int
	)

	flag.StringVar(&listenAddr, "l", "0.0.0.0:2222", "Listen address:port")
	flag.StringVar(&listenPath, "p", "/doh", "Listen https path")
	flag.StringVar(&resolverFile, "f", "./resolvers.txt", "File with resolver list")
	flag.StringVar(&rulesFile, "c", "./rules.conf", "Rules config file")
	flag.StringVar(&certFile, "cert", "./cert.pem", "Certificate file")
	flag.StringVar(&keyFile, "key", "./key.pem", "Certificate private key file")
	flag.StringVar(&testDomain, "domain", "feyro.ir", "Domain used for health checking")
	flag.StringVar(&testIPStr, "ip", "194.180.11.125", "IP used for health checking")
	flag.IntVar(&cacheSize, "cache-size", 10000, "Max cache entries")
	flag.BoolVar(&showStats, "stats", true, "Print stats periodically")
	flag.IntVar(&failGenerosity, "fail-generosity", 10, "Number of failures before DNS server is rejected")

	flag.Parse()

	slog.SetLogLoggerLevel(slog.LevelDebug)
	slog.Info("DNS Balancer")

	testIP := net.ParseIP(testIPStr)
	if testIP == nil {
		slog.Error("invalid test ip")
	}
	slog.Info("Testing servers against", "domain", testDomain, "ip", testIP)

	resolvers := parseResolvers(resolverFile)

	if len(resolvers) == 0 {
		slog.Error("no resolvers parsed")
		os.Exit(1)
	}
	slog.Info("Loaded resolvers", "n", len(resolvers))

	pool := NewResolverPool(resolvers, testDomain, testIP, failGenerosity)

	rules := parseRules(rulesFile)
	slog.Info("Loaded custom rules", "n", len(rules))
	custom := NewCustomResolver(rules)

	cache := NewDNSCache(cacheSize)
	slog.Info("DNS cache enabled", "max_entries", cacheSize)

	doh := NewDoHProxy(listenAddr, listenPath, certFile, keyFile, pool, cache, custom)
	go func() {
		if err := doh.Start(); err != nil {
			slog.Error("Failed to start DoH server", "err", err)
			os.Exit(1)
		}
	}()

	go func() {
		for {
			pool.HealthCheck()
			slog.Info("Health check", "healthy", pool.HealthyCount(), "total", len(pool.resolvers))
			time.Sleep(HealthCheckInterval)
		}
	}()

	if showStats {
		go func() {
			for {
				time.Sleep(StatsInterval)
				slog.Info("Stats", "queries", doh.QueryCount())
				fmt.Fprint(os.Stderr, pool.StatsString())
			}
		}()
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
}

func parseResolvers(file string) []Resolver {
	var resolvers []Resolver

	f, err := os.Open(file)
	if err != nil {
		slog.Error("Failed to open resolvers file", "file", file, "err", err)
	} else {
		defer f.Close()
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			if r, ok := parseOneResolver(line); ok {
				resolvers = append(resolvers, r)
			}
		}
	}

	return resolvers
}

func parseOneResolver(value string) (Resolver, bool) {
	value = strings.TrimSpace(value)
	if strings.Contains(value, ":") {
		return Resolver{Addr: value}, true
	}
	return Resolver{Addr: value + ":53"}, true
}

func parseRules(file string) []CustomRule {
	var rules []CustomRule

	f, err := os.Open(file)
	if err != nil {
		slog.Error("Failed to open rules file", "file", file, "err", err)
		return rules
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		if r, ok := parseOneRule(line); ok {
			rules = append(rules, r)
		}
	}

	if err := scanner.Err(); err != nil {
		slog.Error("Error reading rules file", "err", err)
	}

	return rules
}

func parseOneRule(line string) (CustomRule, bool) {
	line = strings.TrimSpace(line)

	if !strings.HasPrefix(line, "address=") {
		return CustomRule{}, false
	}

	// remove prefix
	line = strings.TrimPrefix(line, "address=")

	// split by "/"
	parts := strings.Split(line, "/")
	if len(parts) < 3 {
		slog.Warn("Invalid rule format", "line", line)
		return CustomRule{}, false
	}

	// ---- Parse IPs (last part) ----
	ipPart := parts[len(parts)-1]
	ipStrs := strings.Split(ipPart, ",")

	var ips []net.IP
	for _, ipStr := range ipStrs {
		ip := net.ParseIP(strings.TrimSpace(ipStr))
		if ip == nil {
			slog.Warn("Invalid IP in rule", "ip", ipStr)
			continue
		}
		ips = append(ips, ip)
	}

	if len(ips) == 0 {
		return CustomRule{}, false
	}

	// ---- Parse domains ----
	domains := parts[1 : len(parts)-1]
	for i := range domains {
		domains[i] = strings.ToLower(strings.TrimSpace(domains[i]))
	}

	return CustomRule{
		Domains: domains,
		IPs:     ips,
	}, true
}
