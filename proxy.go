package main

import (
	"encoding/base64"
	"io"
	"log/slog"
	"net/http"
	"sync/atomic"

	"github.com/miekg/dns"
)

const maxWorkers = 256

type DoHProxy struct {
	listenAddr string
	listenPath string
	certFile   string
	keyFile    string
	pool       *ResolverPool
	cache      *DNSCache
	custom     *CustomResolver
	queryCount uint64
}

func NewDoHProxy(addr string, path string, certFile string, keyFile string, pool *ResolverPool, cache *DNSCache, custom *CustomResolver) *DoHProxy {
	return &DoHProxy{
		listenAddr: addr,
		listenPath: path,
		certFile:   certFile,
		keyFile:    keyFile,
		pool:       pool,
		cache:      cache,
		custom:     custom,
	}
}

func (d *DoHProxy) Start() error {
	slog.Info("DoH starting", "addr", d.listenAddr, "path", d.listenPath)

	http.HandleFunc(d.listenPath, d.HandleQuery)
	err := http.ListenAndServeTLS(d.listenAddr, d.certFile, d.keyFile, nil)
	if err != nil {
		return err
	}

	return nil
}

func (u *DoHProxy) QueryCount() uint64 {
	return atomic.LoadUint64(&u.queryCount)
}

func (d *DoHProxy) HandleQuery(w http.ResponseWriter, r *http.Request) {
	var data []byte
	var err error

	switch r.Method {
	case http.MethodGet:
		dnsParam := r.URL.Query().Get("dns")
		if dnsParam == "" {
			http.Error(w, "Missing dns query parameter", http.StatusBadRequest)
			return
		}

		data, err = base64.RawURLEncoding.DecodeString(dnsParam)
		if err != nil {
			slog.Warn("Invalid base64 dns param", "err", err)
			http.Error(w, "Invalid dns parameter", http.StatusBadRequest)
			return
		}

	case http.MethodPost:
		if ct := r.Header.Get("Content-Type"); ct != "application/dns-message" {
			slog.Warn("Invalid content-type", "ct", ct)
			http.Error(w, "Unsupported media type", http.StatusUnsupportedMediaType)
			return
		}

		data, err = io.ReadAll(r.Body)
		if err != nil {
			slog.Error("Failed reading body", "err", err)
			http.Error(w, "Bad request", http.StatusBadRequest)
			return
		}

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	reqMsg := new(dns.Msg)
	if err := reqMsg.Unpack(data); err != nil {
		slog.Warn("Invalid DNS request", "err", err)
		http.Error(w, "Invalid DNS message", http.StatusBadRequest)
		return
	}

	// Reject IPv6
	if len(reqMsg.Question) > 0 && reqMsg.Question[0].Qtype == dns.TypeAAAA {
		//slog.Debug("Blocked IPv6 query", "name", reqMsg.Question[0].Name)

		resp := new(dns.Msg)
		resp.SetReply(reqMsg)

		// Return NOERROR with empty answer
		resp.Authoritative = true
		resp.RecursionAvailable = true

		buf, err := resp.Pack()
		if err != nil {
			http.Error(w, "Internal error", http.StatusInternalServerError)
			return
		}

		atomic.AddUint64(&d.queryCount, 1)

		w.Header().Set("Content-Type", "application/dns-message")
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusOK)
		w.Write(buf)
		return
	}

	rawResp, err := d.resolve(data)
	if err != nil {
		slog.Error("Resolution failed", "err", err)

		writeDNSFailure(w, reqMsg, dns.RcodeServerFailure)
		return
	}

	respMsg := new(dns.Msg)
	if err := respMsg.Unpack(rawResp); err != nil {
		slog.Error("Invalid DNS response from resolver", "err", err)

		writeDNSFailure(w, reqMsg, dns.RcodeServerFailure)
		return
	}

	buf, err := respMsg.Pack()
	if err != nil {
		slog.Error("Failed to pack DNS response", "err", err)
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}

	atomic.AddUint64(&d.queryCount, 1)

	w.Header().Set("Content-Type", "application/dns-message")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)

	if _, err := w.Write(buf); err != nil {
		slog.Error("Failed writing response", "err", err)
	}
}

func (d *DoHProxy) resolve(data []byte) ([]byte, error) {
	// Check custom rules
	if d.custom != nil {
		if resp, ok := d.custom.Resolve(data); ok {
			return resp, nil
		}
	}

	// Check cache
	if d.cache != nil {
		if resp, ok := d.cache.Get(data); ok {
			return resp, nil
		}
	}

	resolver := d.pool.GetNext()
	d.pool.MarkSent(resolver)

	resp, err := d.pool.SendQuery(data, resolver)
	if err != nil {
		d.pool.MarkFailure(resolver)
		slog.Debug("Forward failed", "resolver", resolver, "err", err)

		// Retry with a different resolver
		retry := d.pool.GetNext()
		if retry != resolver {
			d.pool.MarkSent(retry)
			resp, err = d.pool.SendQuery(data, retry)
			if err != nil {
				d.pool.MarkFailure(retry)
				return nil, err
			}
			d.pool.MarkSuccess(retry)
		} else {
			return nil, err
		}
	} else {
		d.pool.MarkSuccess(resolver)
	}

	if d.cache != nil {
		d.cache.Put(data, resp)
	}

	return resp, nil
}

func writeDNSFailure(w http.ResponseWriter, req *dns.Msg, rcode int) {
	resp := new(dns.Msg)
	resp.SetReply(req)
	resp.Rcode = rcode
	resp.RecursionAvailable = true

	buf, err := resp.Pack()
	if err != nil {
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/dns-message")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	w.Write(buf)
}
