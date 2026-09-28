package main

import (
	"fmt"
	"io"
	"strings"
	"sync/atomic"
	"time"
)

// metrics collects a small set of counters for the /metrics endpoint.
type metrics struct {
	started             time.Time
	statusClass         [5]atomic.Int64 // index: status/100 - 1
	deniedRequests      atomic.Int64
	rateLimitedRequests atomic.Int64
	upstreamErrors      atomic.Int64
	upstreamDurationSum atomic.Int64 // nanoseconds
	upstreamDurationCnt atomic.Int64
	cache               *responseCache // may be nil
}

func newMetrics(cache *responseCache) *metrics {
	return &metrics{started: time.Now(), cache: cache}
}

func (m *metrics) observeStatus(code int) {
	class := code / 100
	if class >= 1 && class <= 5 {
		m.statusClass[class-1].Add(1)
	}
}

func (m *metrics) observeUpstream(d time.Duration, err error) {
	m.upstreamDurationSum.Add(int64(d))
	m.upstreamDurationCnt.Add(1)
	if err != nil {
		m.upstreamErrors.Add(1)
	}
}

func (m *metrics) deny()      { m.deniedRequests.Add(1) }
func (m *metrics) rateLimit() { m.rateLimitedRequests.Add(1) }

// writeProm renders the counters in Prometheus text exposition format.
func (m *metrics) writeProm(w io.Writer) {
	var b strings.Builder
	b.WriteString("# HELP morty_requests_total Proxied requests by response status class\n")
	b.WriteString("# TYPE morty_requests_total counter\n")
	for i, name := range []string{"1xx", "2xx", "3xx", "4xx", "5xx"} {
		fmt.Fprintf(&b, "morty_requests_total{status_class=%q} %d\n", name, m.statusClass[i].Load())
	}
	b.WriteString("# HELP morty_denied_requests_total Requests rejected before fetch\n")
	b.WriteString("# TYPE morty_denied_requests_total counter\n")
	fmt.Fprintf(&b, "morty_denied_requests_total %d\n", m.deniedRequests.Load())
	b.WriteString("# HELP morty_rate_limited_requests_total Requests rejected by the rate limiter\n")
	b.WriteString("# TYPE morty_rate_limited_requests_total counter\n")
	fmt.Fprintf(&b, "morty_rate_limited_requests_total %d\n", m.rateLimitedRequests.Load())
	b.WriteString("# HELP morty_upstream_errors_total Failed upstream fetches\n")
	b.WriteString("# TYPE morty_upstream_errors_total counter\n")
	fmt.Fprintf(&b, "morty_upstream_errors_total %d\n", m.upstreamErrors.Load())
	b.WriteString("# HELP morty_upstream_duration_seconds_sum Total upstream fetch duration\n")
	b.WriteString("# TYPE morty_upstream_duration_seconds_sum counter\n")
	fmt.Fprintf(&b, "morty_upstream_duration_seconds_sum %.6f\n", float64(m.upstreamDurationSum.Load())/1e9)
	b.WriteString("# HELP morty_upstream_duration_seconds_count Completed upstream fetches\n")
	b.WriteString("# TYPE morty_upstream_duration_seconds_count counter\n")
	fmt.Fprintf(&b, "morty_upstream_duration_seconds_count %d\n", m.upstreamDurationCnt.Load())
	b.WriteString("# HELP morty_uptime_seconds Process uptime\n")
	b.WriteString("# TYPE morty_uptime_seconds counter\n")
	fmt.Fprintf(&b, "morty_uptime_seconds %.0f\n", time.Since(m.started).Seconds())
	if m.cache != nil {
		hits, misses, entries, used := m.cache.stats()
		b.WriteString("# HELP morty_cache_hits_total Cache hits\n")
		b.WriteString("# TYPE morty_cache_hits_total counter\n")
		fmt.Fprintf(&b, "morty_cache_hits_total %d\n", hits)
		b.WriteString("# HELP morty_cache_misses_total Cache misses\n")
		b.WriteString("# TYPE morty_cache_misses_total counter\n")
		fmt.Fprintf(&b, "morty_cache_misses_total %d\n", misses)
		b.WriteString("# HELP morty_cache_entries Cached entries\n")
		b.WriteString("# TYPE morty_cache_entries gauge\n")
		fmt.Fprintf(&b, "morty_cache_entries %d\n", entries)
		b.WriteString("# HELP morty_cache_bytes Cache size in bytes\n")
		b.WriteString("# TYPE morty_cache_bytes gauge\n")
		fmt.Fprintf(&b, "morty_cache_bytes %d\n", used)
	}
	io.WriteString(w, b.String())
}
