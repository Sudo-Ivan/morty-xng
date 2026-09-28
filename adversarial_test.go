package main

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/valyala/fasthttp"
	"go.uber.org/goleak"
)

// TestAdversarialURIInputs feeds hostile URI strings through sanitizeURI
// and ProxifyURI. None may panic, and dangerous schemes must never pass.
func TestAdversarialURIInputs(t *testing.T) {
	u, _ := url.Parse("http://base.example/")
	rc := &RequestConfig{BaseURL: u}

	dangerous := []string{
		"java\tscript:alert(1)",
		"java\nscript:alert(1)",
		"JAVASCRIPT:alert(1)",
		"  javascript:alert(1)",
		"javascript :alert(1)",
		"vbscript:msgbox(1)",
		"data:text/html;base64,PGJhc2U+",
		"data:image/svg+xml;base64,AAA",
		"data:image/pngx;base64,AAA",
		"\x00\x01\x02javascript:alert(1)",
	}
	for _, in := range dangerous {
		out, err := rc.ProxifyURI([]byte(in))
		if err == nil && strings.Contains(strings.ToLower(out), "mortyurl=javascript") {
			t.Errorf("dangerous scheme proxified: %q -> %q", in, out)
		}
		if err == nil && strings.HasPrefix(strings.TrimSpace(out), "javascript:") {
			t.Errorf("javascript passed through: %q -> %q", in, out)
		}
	}

	// giant input must not hang or crash
	big := strings.Repeat("a", 1<<20) + "://x"
	rc.ProxifyURI([]byte(big))                        //nolint:errcheck
	rc.ProxifyURI([]byte(strings.Repeat("?", 1<<16))) //nolint:errcheck

	// embedded credentials and unusual hosts must still be proxified
	for _, in := range []string{
		"http://user:p%40ss@h.example/x",
		"//proto-relative.example/p",
		"http://[2001:db8::1]:8080/p",
		"HTTP://UPPER.EXAMPLE/Path",
		"http://host.example/a/../b?x=%2F",
	} {
		out, err := rc.ProxifyURI([]byte(in))
		if err != nil {
			t.Errorf("legit-looking uri failed: %q: %v", in, err)
		} else if out == "" {
			t.Errorf("empty output for %q", in)
		}
	}
}

// TestAdversarialHTML feeds malformed and hostile documents through the
// sanitizer. No unsafe element or raw attribute may survive.
func TestAdversarialHTML(t *testing.T) {
	u, _ := url.Parse("http://base.example/")
	rc := &RequestConfig{BaseURL: u}

	cases := []struct {
		name    string
		input   string
		mustNot []string
	}{
		{"null bytes", "<p\x00 onclick='x()'>t</p\x00>", []string{"onclick"}},
		{"unclosed script", "<script>alert(1)", []string{"<script"}},
		{"script in attr", "<a href=\"javas%63ript:x\">y</a>", []string{}},
		{"nested script 10x", strings.Repeat("<scr"+"ipt>", 10) + "x" + strings.Repeat("</script>", 10), []string{"<script"}},
		{"formaction js", `<button formaction="javascript:alert(1)">`, []string{"javascript"}},
		{"srcdoc attack", `<iframe srcdoc="&lt;img src=x onerror=alert(1)&gt;">`, []string{"onerror"}},
		{"base hijack", `<base href="javascript:alert(1)"><a href=/x>`, []string{"<base"}},
		{"style expr", `<a style="width:expression(alert(1))">`, []string{"expression("}},
		{"deep nesting", strings.Repeat("<div><a href='/x'>", 500) + strings.Repeat("</a></div>", 500), []string{}},
		{"meta refresh js", `<meta http-equiv=refresh content="0;url=javascript:alert(1)">`, []string{"javascript"}},
		{"svg smuggle", `<svg><a href=/x><text>t</text></a></svg><p>ok</p>`, []string{"<svg"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out := bytes.NewBuffer(nil)
			sanitizeHTML(rc, out, []byte(tc.input))
			got := out.String()
			for _, bad := range tc.mustNot {
				if strings.Contains(strings.ToLower(got), bad) {
					t.Errorf("%q survives in output: %s", bad, got[:min(len(got), 300)])
				}
			}
		})
	}
}

// TestAdversarialRequestMerge proves that extra query parameters are
// merged into the upstream URL without corrupting the args buffer.
func TestAdversarialRequestMerge(t *testing.T) {
	var gotURI string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotURI = r.URL.String()
		io.WriteString(w, "ok")
	}))
	defer upstream.Close()

	p := &Proxy{RequestTimeout: 5 * time.Second}
	base := startProxy(t, p)

	target := upstream.URL + "/path?orig=1"
	httpGet(t, base+"/?mortyurl="+url.QueryEscape(target)+"&extra=2&flag")
	want := "/path?orig=1&extra=2&flag"
	if gotURI != want {
		t.Fatalf("merged upstream uri = %q, want %q", gotURI, want)
	}
}

// TestAdversarialOnionWithPort is a regression test: a port suffix must
// not bypass the .onion exit page.
func TestAdversarialOnionWithPort(t *testing.T) {
	p := &Proxy{RequestTimeout: 5 * time.Second}
	base := startProxy(t, p)
	status, _, _ := httpGet(t, base+"/?mortyurl="+url.QueryEscape("http://check.torproject.org.onion:8080/"))
	if status != fasthttp.StatusForbidden {
		t.Fatalf("onion+port should hit exit page (403), got %d", status)
	}
}

// TestAdversarialRedirectToPrivate ensures redirect following cannot be
// used to reach private addresses.
func TestAdversarialRedirectToPrivate(t *testing.T) {
	oldDial := client.Dial
	client.Dial = secureDialer(true, false, newDNSCache(time.Minute), 2*time.Second)
	defer func() { client.Dial = oldDial }()

	// upstream redirects to 127.0.0.1 - the hop must be blocked
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", "http://127.0.0.1:1/")
		w.WriteHeader(http.StatusFound)
	}))
	defer upstream.Close()

	p := &Proxy{RequestTimeout: 5 * time.Second, FollowRedirect: true}
	base := startProxy(t, p)
	status, _, _ := httpGet(t, base+"/?mortyurl="+url.QueryEscape(upstream.URL+"/"))
	if status != fasthttp.StatusInternalServerError {
		t.Fatalf("redirect to private IP should fail (500), got %d", status)
	}
}

// TestAdversarialOversizedPost verifies the server body size limit.
func TestAdversarialOversizedPost(t *testing.T) {
	p := &Proxy{RequestTimeout: 5 * time.Second}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &fasthttp.Server{Handler: p.RequestHandler, MaxRequestBodySize: 1024}
	go srv.Serve(ln)     //nolint:errcheck
	defer srv.Shutdown() //nolint:errcheck
	base := "http://" + ln.Addr().String()

	resp, err := http.Post(base+"/", "text/plain", strings.NewReader(strings.Repeat("x", 4096)))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode/100 != 4 {
		t.Fatalf("oversized post: expected 4xx rejection, got %d", resp.StatusCode)
	}
}

// TestConcurrentRequests exercises the handler under parallel load for
// the race detector and shared state (limiter, cache).
func TestConcurrentRequests(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		io.WriteString(w, `<html><body><a href=/x>x</a></body></html>`)
	}))
	defer upstream.Close()

	p := &Proxy{
		RequestTimeout: 5 * time.Second,
		Cache:          newResponseCache(1<<20, time.Minute),
		Metrics:        newMetrics(nil),
	}
	base := startProxy(t, p)
	u := base + "/?mortyurl=" + url.QueryEscape(upstream.URL+"/")

	var wg sync.WaitGroup
	errs := make(chan error, 64)
	for i := 0; i < 64; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			status, _, body := httpGet(t, u)
			if status != 200 {
				errs <- fmt.Errorf("req %d: status %d", i, status)
			} else if !strings.Contains(body, "mortyurl=") {
				errs <- fmt.Errorf("req %d: not proxified", i)
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		t.Error(e)
	}
}

// TestGoroutineLeak verifies the request path does not leak goroutines.
func TestGoroutineLeak(t *testing.T) {
	defer goleak.VerifyNone(t,
		// fasthttp keeps worker pools, cleaners and the shared server
		// date updater alive for connection reuse; they are pooled
		// process-wide singletons, not leaks
		goleak.IgnoreAnyFunction("github.com/valyala/fasthttp.(*workerPool).Start.func2"),
		goleak.IgnoreAnyFunction("github.com/valyala/fasthttp.(*HostClient).connsCleaner"),
		goleak.IgnoreAnyFunction("github.com/valyala/fasthttp.(*Client).mCleaner"),
		goleak.IgnoreAnyFunction("github.com/valyala/fasthttp.(*TCPDialer).tcpAddrsClean"),
		goleak.IgnoreAnyFunction("github.com/valyala/fasthttp.updateServerDate.func1"),
		goleak.IgnoreAnyFunction("net/http.(*persistConn).readLoop"),
		goleak.IgnoreAnyFunction("net/http.(*persistConn).writeLoop"),
	)

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "ok")
	}))
	defer upstream.Close()

	p := &Proxy{RequestTimeout: 5 * time.Second}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &fasthttp.Server{Handler: p.RequestHandler}
	go srv.Serve(ln) //nolint:errcheck
	base := "http://" + ln.Addr().String()

	client := &http.Client{}
	for i := 0; i < 10; i++ {
		resp, err := client.Get(base + "/?mortyurl=" + url.QueryEscape(upstream.URL+"/"))
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
	}
	client.CloseIdleConnections()
	srv.Shutdown() //nolint:errcheck

	// give the runtime a moment to wind down listeners
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if runtime.NumGoroutine() < 20 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
}
