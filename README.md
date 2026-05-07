# dns-balancer

A DNS-over-HTTPS (DoH) proxy that distributes queries across a pool of upstream UDP resolvers.  
It includes health checking, caching, custom static rules (dnsmasq style) and explicit IPv6 blocking.

Forked from [DNS-Multiplexer](https://github.com/anonvector/DNS-Multiplexer).

## Features

- **Multiplexing** - load-balance queries over multiple UDP-based DNS resolvers.
- **Health checking** - periodic checks keep unresponsive resolvers out of the pool.
- **DNS-over-HTTPS** - exposes a standard `application/dns-message` endpoint (GET and POST).
- **Custom rules** - define static `A`-record mappings with dnsmasq-like syntax and round-robin IP replies.
- **IPv6 blocking** - all AAAA queries are answered with an empty NOERROR response (useful in networks without IPv6 connectivity).
- **LRU cache** - stores responses based on the minimum TTL found in the answer/authority/additional sections; rewrites transaction IDs to match incoming queries.
- **Resilience** - a configurable failure streak threshold prevents isolated timeouts from evicting a good resolver.

## Quick Start

```bash
# Build
go build -o dns-balancer .

# Run (replace certificate files with your own)
./dns-balancer \
  -l 0.0.0.0:2222 \
  -p /doh \
  -f resolvers.txt \
  -c rules.conf \
  -cert cert.pem \
  -key key.pem
```

The server will listen for DoH requests at `https://<your-ip>:2222/doh`.

## Command-line Flags

| Flag               | Default            | Description |
|--------------------|--------------------|-------------|
| `-l`               | `0.0.0.0:2222`     | Listen address and port |
| `-p`               | `/doh`             | URL path for the DoH endpoint |
| `-f`               | `./resolvers.txt`  | File with upstream UDP resolvers |
| `-c`               | `./rules.conf`     | Custom rules file (dnsmasq address format) |
| `-cert`            | `./cert.pem`       | TLS certificate |
| `-key`             | `./key.pem`        | TLS private key |
| `-domain`          | `feyro.ir`         | Domain used for health checks |
| `-ip`              | `194.180.11.125`   | Expected A record IP for health checks |
| `-cache-size`      | `10000`            | Maximum cache entries (LRU) |
| `-stats`           | `true`             | Print resolver stats every 60 seconds |
| `-fail-generosity` | `10`               | Consecutive UDP failures before a resolver is marked unhealthy |

## Upstream Resolver File (`-f`)

One resolver per line. Lines starting with `#` or empty lines are ignored.  
If no port is given, `:53` is appended.

```
# Example resolvers.txt
8.8.8.8
1.1.1.1:53
208.67.222.222:5353
```

## Custom Rules File (`-c`)

Supports dnsmasq-style `address` rules that serve static A records for one or more domains.  
Format:

```
address=/domain1/domain2/.../ip1,ip2,...
```

- Domains are matched as suffixes (e.g. `example.com` matches `www.example.com` and `example.com`).
- Multiple IPs are used in round-robin order.
- Only `A` queries are answered; other types are passed through to the resolvers.

```
# Example rules.conf
address=/blocked.com/0.0.0.0
address=/cdn.example.net/cdn.example.org/10.0.0.1,10.0.0.2
```

## Health Check Mechanism

Every 30 seconds the proxy sends a recursive `A` query for the configured test domain to **all** resolvers.  
A resolver is considered healthy only if:

- The UDP query succeeds.
- The response contains the expected test IP.

When a resolver accumulates `-fail-generosity` consecutive failures, it is marked unhealthy and removed from the round-robin pool until a future health check succeeds.  

## Resolver Pool Behaviour

- Queries are distributed using **round-robin** among healthy resolvers.
- On first failure, the proxy **retries once** with a different healthy resolver before returning an error.
- The `-fail-generosity` flag controls the sensitivity to transient failures (e.g. during internet shutdowns).

## Caching

Responses are cached using an LRU map with TTL-based expiry.  
The cache key is `(QNAME, QTYPE, QCLASS)` and the TTL is the **minimum** TTL found in the answer, authority and additional sections (OPT records excluded).  
On cache hits the two-byte DNS transaction ID is rewritten to match the client’s query, ensuring transparent replies.

## IPv6 Handling

All `AAAA` queries are immediately answered with a standard `NOERROR` response containing zero answers (authoritative and recursion-available flags set).  
This is intentional because of environments where IPv6 connectivity is unreliable and filtering it at the DNS level improves user experience.

## Stats

When `-stats` is enabled (default), the proxy prints to `stderr` every 60 seconds:

- Total DoH queries served.
- Per-resolver counters: `sent`, `ok`, `fail`.
