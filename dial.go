package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/valyala/fasthttp"
)

// errForbiddenAddress is returned when a request targets a private or
// reserved IP range and private access is not allowed.
var errForbiddenAddress = errors.New("forbidden private or reserved address")

// privateRanges covers non-public IPv4/IPv6 ranges that must never be
// contacted by the proxy: loopback, link-local (cloud metadata lives
// under 169.254.0.0/16), private, CGNAT, documentation, multicast and
// reserved space.
var privateRanges = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("224.0.0.0/4"),
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("::/128"),
	netip.MustParsePrefix("::1/128"),
	netip.MustParsePrefix("fc00::/7"),
	netip.MustParsePrefix("fe80::/10"),
	netip.MustParsePrefix("ff00::/8"),
	netip.MustParsePrefix("2001:db8::/32"),
}

// isPrivateIP reports whether ip belongs to a private or reserved range.
// IPv4-mapped IPv6 addresses are unmapped before the check.
func isPrivateIP(ip netip.Addr) bool {
	ip = ip.Unmap()
	if !ip.IsGlobalUnicast() || ip.IsPrivate() {
		return true
	}
	for _, p := range privateRanges {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

// dnsCache caches name resolutions for a short TTL to avoid a lookup per
// proxified resource while still defeating stale answers.
type dnsCache struct {
	mu      sync.Mutex
	entries map[string]dnsEntry
	ttl     time.Duration
}

type dnsEntry struct {
	ips     []netip.Addr
	expires time.Time
}

func newDNSCache(ttl time.Duration) *dnsCache {
	return &dnsCache{entries: make(map[string]dnsEntry), ttl: ttl}
}

func (c *dnsCache) lookup(ctx context.Context, host string) ([]netip.Addr, error) {
	c.mu.Lock()
	e, ok := c.entries[host]
	c.mu.Unlock()

	if ok && time.Now().Before(e.expires) {
		return e.ips, nil
	}

	ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return nil, err
	}

	c.mu.Lock()
	c.entries[host] = dnsEntry{ips: ips, expires: time.Now().Add(c.ttl)}
	c.mu.Unlock()

	return ips, nil
}

// secureDialer returns a fasthttp DialFunc that resolves hostnames, blocks
// private/reserved targets unless allowPrivate is set, dials the resolved
// address directly to prevent DNS rebinding, and caches resolutions.
// When ipv6 is false, AAAA results are skipped.
func secureDialer(ipv6, allowPrivate bool, dns *dnsCache, dialTimeout time.Duration) fasthttp.DialFunc {
	return func(addr string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			// fasthttp passes host:port, but tolerate a bare host
			host, port = addr, "443"
		}

		ctx, cancel := context.WithTimeout(context.Background(), dialTimeout)
		defer cancel()

		ips, err := dns.lookup(ctx, host)
		if err != nil {
			return nil, err
		}

		dialer := &net.Dialer{Timeout: dialTimeout}
		blocked := 0
		var lastErr error
		for _, ip := range ips {
			if !allowPrivate && isPrivateIP(ip) {
				blocked++
				continue
			}
			if !ipv6 && ip.Is6() {
				continue
			}
			conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(ip.String(), port))
			if err == nil {
				return conn, nil
			}
			lastErr = err
		}

		if blocked > 0 && lastErr == nil {
			return nil, fmt.Errorf("%w: %s", errForbiddenAddress, host)
		}
		if blocked > 0 {
			return nil, fmt.Errorf("%w: %s (dial failed: %v)", errForbiddenAddress, host, lastErr)
		}
		if lastErr == nil {
			return nil, fmt.Errorf("no usable address for %s", host)
		}
		return nil, fmt.Errorf("cannot dial %s: %w", host, lastErr)
	}
}

// hostAllowed checks a hostname against allow and deny suffix lists.
// A deny match always wins; when the allowlist is non-empty a match is
// required. Suffixes match the exact host and any subdomain.
func hostAllowed(host string, allow, deny []string) bool {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	for _, d := range deny {
		if host == d || strings.HasSuffix(host, "."+d) {
			return false
		}
	}
	if len(allow) == 0 {
		return true
	}
	for _, a := range allow {
		if host == a || strings.HasSuffix(host, "."+a) {
			return true
		}
	}
	return false
}

// splitHostList splits a comma separated host list and normalizes entries.
func splitHostList(list string) []string {
	var out []string
	for _, h := range strings.Split(list, ",") {
		h = strings.ToLower(strings.TrimSpace(h))
		if h != "" {
			out = append(out, h)
		}
	}
	return out
}
