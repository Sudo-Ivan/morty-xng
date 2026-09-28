package main

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/valyala/fasthttp"
)

type attrTestCase struct {
	attrName       []byte
	attrValue      []byte
	expectedOutput []byte
}

type sanitizeURITestCase struct {
	input          []byte
	expectedOutput []byte
	expectedScheme string
}

type stringTestCase struct {
	input          string
	expectedOutput string
}

var attrTestData = []*attrTestCase{
	{
		[]byte("href"),
		[]byte("./x"),
		[]byte(` href="./?mortyurl=http%3A%2F%2F127.0.0.1%2Fx"`),
	},
	{
		[]byte("src"),
		[]byte("http://x.com/y"),
		[]byte(` src="./?mortyurl=http%3A%2F%2Fx.com%2Fy"`),
	},
	{
		[]byte("action"),
		[]byte("/z"),
		[]byte(` action="./?mortyurl=http%3A%2F%2F127.0.0.1%2Fz"`),
	},
	{
		[]byte("onclick"),
		[]byte("console.log(document.cookies)"),
		nil,
	},
	{
		[]byte("href"),
		[]byte("javascript:alert(1)"),
		[]byte(` href=""`),
	},
}

var sanitizeURITestData = []*sanitizeURITestCase{
	{
		[]byte("http://example.com/"),
		[]byte("http://example.com/"),
		"http:",
	},
	{
		[]byte("HtTPs://example.com/     \t"),
		[]byte("https://example.com/"),
		"https:",
	},
	{
		[]byte("      Ht  TPs://example.com/     \t"),
		[]byte("https://example.com/"),
		"https:",
	},
	{
		[]byte("javascript:void(0)"),
		[]byte("javascript:void(0)"),
		"javascript:",
	},
	{
		[]byte("      /path/to/a/file/without/protocol     "),
		[]byte("/path/to/a/file/without/protocol"),
		"",
	},
	{
		[]byte("      #fragment     "),
		[]byte("#fragment"),
		"",
	},
	{
		[]byte("      qwertyuiop     "),
		[]byte("qwertyuiop"),
		"",
	},
	{
		[]byte(""),
		[]byte(""),
		"",
	},
	{
		[]byte(":"),
		[]byte(":"),
		":",
	},
	{
		[]byte("   :"),
		[]byte(":"),
		":",
	},
	{
		[]byte("schéma:"),
		[]byte("schéma:"),
		"schéma:",
	},
}

var urlTestData = []*stringTestCase{
	{
		"http://x.com/",
		"./?mortyurl=http%3A%2F%2Fx.com%2F",
	},
	{
		"http://a@x.com/",
		"./?mortyurl=http%3A%2F%2Fa%40x.com%2F",
	},
	{
		"#a",
		"#a",
	},
	{
		"javascript:alert(1)",
		"",
	},
	{
		"data:text/html;base64,PHNjcmlwdD4=",
		"",
	},
	{
		"data:image/png;base64,iVBORw0KGgo=",
		"data:image/png;base64,iVBORw0KGgo=",
	},
	{
		"vbscript:msgbox(1)",
		"",
	},
}

func TestAttrSanitizer(t *testing.T) {
	u, _ := url.Parse("http://127.0.0.1/")
	rc := &RequestConfig{BaseURL: u}
	for _, testCase := range attrTestData {
		out := bytes.NewBuffer(nil)
		sanitizeAttr(rc, out, testCase.attrName, testCase.attrValue, testCase.attrValue)
		res, _ := out.ReadBytes(byte(0))
		if !bytes.Equal(res, testCase.expectedOutput) {
			t.Errorf(
				`Attribute parse error. Name: "%s", Value: "%s", Expected: %s, Got: "%s"`,
				testCase.attrName,
				testCase.attrValue,
				testCase.expectedOutput,
				res,
			)
		}
	}
}

func TestSanitizeURI(t *testing.T) {
	for _, testCase := range sanitizeURITestData {
		// sanitizeURI mutates its input, always pass a copy
		input := append([]byte(nil), testCase.input...)
		newURL, scheme := sanitizeURI(input)
		if !bytes.Equal(newURL, testCase.expectedOutput) {
			t.Errorf(
				`URL proxifier error. Expected: "%s", Got: "%s"`,
				testCase.expectedOutput,
				newURL,
			)
		}
		if scheme != testCase.expectedScheme {
			t.Errorf(
				`URL proxifier error. Expected: "%s", Got: "%s"`,
				testCase.expectedScheme,
				scheme,
			)
		}
	}
}

func TestURLProxifier(t *testing.T) {
	u, _ := url.Parse("http://127.0.0.1/")
	rc := &RequestConfig{BaseURL: u}
	for _, testCase := range urlTestData {
		newURL, err := rc.ProxifyURI([]byte(testCase.input))
		if err != nil {
			t.Errorf("Failed to parse URL: %s", testCase.input)
		}
		if newURL != testCase.expectedOutput {
			t.Errorf(
				`URL proxifier error. Expected: "%s", Got: "%s"`,
				testCase.expectedOutput,
				newURL,
			)
		}
	}
}

func TestURLProxifierWithKey(t *testing.T) {
	u, _ := url.Parse("http://127.0.0.1/")
	key := []byte("secret-key")
	rc := &RequestConfig{BaseURL: u, Key: key}

	out, err := rc.ProxifyURI([]byte("http://x.com/a?b=1"))
	if err != nil {
		t.Fatal(err)
	}
	expected := fmt.Sprintf("./?mortyhash=%s&mortyurl=http%%3A%%2F%%2Fx.com%%2Fa%%3Fb%%3D1", hash("http://x.com/a?b=1", key))
	if out != expected {
		t.Fatalf("unexpected proxified URL:\nexpected: %s\ngot:      %s", expected, out)
	}

	// the hash inside the output must validate against the raw URL
	parsed, err := url.Parse(strings.TrimPrefix(out, "./"))
	if err != nil {
		t.Fatal(err)
	}
	mortyHash := parsed.Query().Get("mortyhash")
	mortyURL := parsed.Query().Get("mortyurl")
	if mortyURL != "http://x.com/a?b=1" {
		t.Fatalf("unexpected mortyurl: %s", mortyURL)
	}
	if !verifyRequestURI([]byte(mortyURL), []byte(mortyHash), key) {
		t.Fatal("mortyhash does not verify")
	}
}

func TestVerifyRequestURI(t *testing.T) {
	key := []byte("test-key")
	uri := []byte("https://example.com/path?q=1")
	validHash := []byte(hash(string(uri), key))

	if !verifyRequestURI(uri, validHash, key) {
		t.Error("valid HMAC rejected")
	}
	if verifyRequestURI(uri, []byte("deadbeef"), key) {
		t.Error("invalid HMAC accepted")
	}
	if verifyRequestURI(uri, nil, key) {
		t.Error("missing HMAC accepted")
	}
	if verifyRequestURI([]byte("https://other.example/"), validHash, key) {
		t.Error("HMAC for a different URL accepted")
	}
	if verifyRequestURI(uri, []byte("not-hex!!"), key) {
		t.Error("non-hex HMAC accepted")
	}
}

func TestHash(t *testing.T) {
	got := hash("https://example.com/", []byte("key"))
	expected := "95d15e0d390979b8848afb0e36aa2ed3ff6e0daccf90228fee16061c6607284b"
	if got != expected {
		t.Fatalf("unexpected hash: got %s expected %s", got, expected)
	}
}

func TestSanitizeFilename(t *testing.T) {
	cases := []struct {
		input    string
		expected string
	}{
		{"file.pdf", "file.pdf"},
		{"../../etc/passwd", "etcpasswd"}, // separators and dots are stripped
		{`bad"name".txt`, "badname.txt"},
		{"a\rb\nc.txt", "abc.txt"},
		{"   spaced.txt   ", "spaced.txt"},
		{"", "download"},
		{"...", "download"},
		{strings.Repeat("a", 200), "download"},
	}
	for _, c := range cases {
		if got := sanitizeFilename(c.input); got != c.expected {
			t.Errorf("sanitizeFilename(%q): expected %q, got %q", c.input, c.expected, got)
		}
	}
}

func TestContentDispositionForceAttachment(t *testing.T) {
	u, _ := url.Parse("http://example.com/dir/report.pdf")
	out := string(contentDispositionForceAttachment(nil, u))
	if !strings.HasPrefix(out, "attachment;") || !strings.Contains(out, "filename=report.pdf") {
		t.Fatalf("unexpected content-disposition: %s", out)
	}

	// an existing filename must be preserved
	u2, _ := url.Parse("http://example.com/noext")
	out2 := string(contentDispositionForceAttachment([]byte(`attachment; filename="orig.bin"`), u2))
	if !strings.Contains(out2, "orig.bin") {
		t.Fatalf("existing filename lost: %s", out2)
	}
}

func TestPopRequestParam(t *testing.T) {
	var ctx fasthttp.RequestCtx
	ctx.Request.SetRequestURI("/?mortyurl=http%3A%2F%2Fexample.com%2F&mortyhash=abc&keep=1")

	if got := popRequestParam(&ctx, []byte("mortyurl")); string(got) != "http://example.com/" {
		t.Fatalf("unexpected mortyurl: %s", got)
	}
	if got := popRequestParam(&ctx, []byte("mortyhash")); string(got) != "abc" {
		t.Fatalf("unexpected mortyhash: %s", got)
	}
	if got := ctx.QueryArgs().Peek("keep"); string(got) != "1" {
		t.Fatal("unrelated query parameter was removed")
	}
	if got := ctx.QueryArgs().Peek("mortyurl"); got != nil {
		t.Fatal("mortyurl still present in query args")
	}

	// parameters in the POST body
	var postCtx fasthttp.RequestCtx
	postCtx.Request.Header.SetMethod("POST")
	postCtx.Request.Header.SetContentType("application/x-www-form-urlencoded")
	postCtx.Request.SetBodyString("mortyurl=http%3A%2F%2Fpost.example%2F&field=x")
	if got := popRequestParam(&postCtx, []byte("mortyurl")); string(got) != "http://post.example/" {
		t.Fatalf("unexpected POST mortyurl: %s", got)
	}
	if got := postCtx.PostArgs().Peek("field"); string(got) != "x" {
		t.Fatal("unrelated POST field was removed")
	}
}

func TestProxifySrcSet(t *testing.T) {
	u, _ := url.Parse("http://127.0.0.1/")
	rc := &RequestConfig{BaseURL: u}
	got := proxifySrcSet(rc, []byte("/a.png 1x, /b.png 2x"))
	for _, want := range []string{"./?mortyurl=http%3A%2F%2F127.0.0.1%2Fa.png 1x", "./?mortyurl=http%3A%2F%2F127.0.0.1%2Fb.png 2x"} {
		if !strings.Contains(got, want) {
			t.Errorf("srcset output missing %q: %s", want, got)
		}
	}
}

type sanitizeHTMLCase struct {
	name        string
	input       string
	mustContain []string
	mustNot     []string
}

var sanitizeHTMLCases = []sanitizeHTMLCase{
	{
		name:        "script stripped",
		input:       `<html><body><script>alert(1)</script><p>ok</p></body></html>`,
		mustContain: []string{"<p>ok</p>"},
		mustNot:     []string{"script", "alert"},
	},
	{
		name:        "inline handler dropped",
		input:       `<html><body><a href="/x" onclick="steal()">link</a></body></html>`,
		mustContain: []string{`href="./?mortyurl=`},
		mustNot:     []string{"onclick", "steal"},
	},
	{
		name:        "img src proxified",
		input:       `<html><body><img src="/i.png" alt="pic" /></body></html>`,
		mustContain: []string{`src="./?mortyurl=http%3A%2F%2Fbase.example%2Fi.png"`, `alt="pic"`},
	},
	{
		name:        "noscript tag removed, content kept",
		input:       `<html><body><noscript><p>nojs</p></noscript></body></html>`,
		mustContain: []string{"<p>nojs</p>"},
		mustNot:     []string{"noscript"},
	},
	{
		name:        "comment removed",
		input:       `<html><body><!-- secret --><p>ok</p></body></html>`,
		mustContain: []string{"<p>ok</p>"},
		mustNot:     []string{"secret"},
	},
	{
		name:        "meta charset dropped",
		input:       `<html><head><meta charset="utf-8"></head><body>x</body></html>`,
		mustNot:     []string{`charset="utf-8"`},
		mustContain: []string{`http-equiv="Content-Type"`},
	},
	{
		name:        "meta refresh proxified",
		input:       `<html><head><meta http-equiv="refresh" content="0; URL=/next"></head><body>x</body></html>`,
		mustContain: []string{`mortyurl=http%3A%2F%2Fbase.example%2Fnext`},
	},
	{
		name:        "link stylesheet kept",
		input:       `<html><head><link rel="stylesheet" href="/s.css"></head><body>x</body></html>`,
		mustContain: []string{`rel="stylesheet"`, `mortyurl=http%3A%2F%2Fbase.example%2Fs.css`},
	},
	{
		name:        "link preload script dropped",
		input:       `<html><head><link rel="preload" as="script" href="/e.js"></head><body>x</body></html>`,
		mustNot:     []string{"preload", "e.js"},
		mustContain: []string{"x"},
	},
	{
		name:        "svg and embed stripped",
		input:       `<html><body><svg onload="x()"></svg><embed src="/e.swf"><p>ok</p></body></html>`,
		mustContain: []string{"<p>ok</p>"},
		mustNot:     []string{"svg", "embed", "swf"},
	},
	{
		name:        "form gets hidden inputs",
		input:       `<html><body><form action="/search"><input name="q"></form></body></html>`,
		mustContain: []string{`name="mortyurl"`, `value="http://base.example/search"`},
	},
	{
		name:        "base href resolved",
		input:       `<html><head><base href="http://other.example/sub/"></head><body><a href="rel">l</a></body></html>`,
		mustContain: []string{`mortyurl=http%3A%2F%2Fother.example%2Fsub%2Frel`},
	},
	{
		name:        "style attr rewritten",
		input:       `<html><body><div style="background: url(/bg.png)">x</div></body></html>`,
		mustContain: []string{`style="`, `mortyurl=http%3A%2F%2Fbase.example%2Fbg.png`},
	},
	{
		name:        "javascript href removed",
		input:       `<html><body><a href="javascript:alert(1)">x</a></body></html>`,
		mustNot:     []string{"javascript", "alert"},
		mustContain: []string{">x<"},
	},
	{
		name:        "iframe allowed and proxified",
		input:       `<html><body><iframe src="/frame"></iframe></body></html>`,
		mustContain: []string{`iframe`, `mortyurl=http%3A%2F%2Fbase.example%2Fframe`},
	},
	{
		name:        "nested unsafe elements stripped",
		input:       `<html><body><script>var a = "<scr"+"ipt>";</script><math><mtext>x</mtext></math><p>ok</p></body></html>`,
		mustContain: []string{"<p>ok</p>"},
		mustNot:     []string{"<script", "<math"},
	},
}

func TestSanitizeHTML(t *testing.T) {
	for _, tc := range sanitizeHTMLCases {
		t.Run(tc.name, func(t *testing.T) {
			u, _ := url.Parse("http://base.example/")
			rc := &RequestConfig{BaseURL: u}
			out := bytes.NewBuffer(nil)
			sanitizeHTML(rc, out, []byte(tc.input))
			got := out.String()
			for _, want := range tc.mustContain {
				if !strings.Contains(got, want) {
					t.Errorf("output missing %q\noutput: %s", want, got)
				}
			}
			for _, unwanted := range tc.mustNot {
				if strings.Contains(got, unwanted) {
					t.Errorf("output contains %q\noutput: %s", unwanted, got)
				}
			}
		})
	}
}

func TestSanitizeHTMLBodyInjection(t *testing.T) {
	u, _ := url.Parse("http://base.example/page")
	rc := &RequestConfig{BaseURL: u}
	out := bytes.NewBuffer(nil)
	sanitizeHTML(rc, out, []byte(`<html><body><p>x</p></body></html>`))
	if !rc.BodyInjected {
		t.Error("BodyInjected flag not set after </body>")
	}
	if !strings.Contains(out.String(), "mortyheader") {
		t.Error("morty header not injected before </body>")
	}
}

func TestSanitizeCSS(t *testing.T) {
	u, _ := url.Parse("http://base.example/css/")
	rc := &RequestConfig{BaseURL: u}
	out := bytes.NewBuffer(nil)
	sanitizeCSS(rc, out, []byte(`a { background: url("/img.png"); } b { background: url(data:image/png;base64,AAAA); }`))
	got := out.String()
	if !strings.Contains(got, `url("./?mortyurl=http%3A%2F%2Fbase.example%2Fimg.png")`) {
		t.Errorf("css url not proxified: %s", got)
	}
	if !strings.Contains(got, "data:image/png;base64,AAAA") {
		t.Errorf("safe data uri removed: %s", got)
	}
}

// startProxy launches the proxy handler on a local TCP port for
// handler-level integration tests.
func startProxy(t *testing.T, p *Proxy) string {
	t.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &fasthttp.Server{Handler: p.RequestHandler}
	go srv.Serve(ln) //nolint:errcheck
	t.Cleanup(func() {
		srv.Shutdown() //nolint:errcheck
	})
	return fmt.Sprintf("http://127.0.0.1:%d", ln.Addr().(*net.TCPAddr).Port)
}

func httpGet(t *testing.T, rawURL string) (int, http.Header, string) {
	t.Helper()
	httpClient := &http.Client{Timeout: 10 * time.Second}
	resp, err := httpClient.Get(rawURL)
	if err != nil {
		t.Fatalf("GET %s: %v", rawURL, err)
	}
	defer resp.Body.Close() //nolint:errcheck
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, resp.Header, string(body)
}

func TestProxyEndToEnd(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/page":
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			io.WriteString(w, `<!doctype html><html><head><script>evil()</script></head><body><img src="/i.png"><p>hi</p></body></html>`)
		case "/doc.pdf":
			w.Header().Set("Content-Type", "application/pdf")
			io.WriteString(w, "%PDF-fake")
		case "/secret.js":
			w.Header().Set("Content-Type", "text/javascript")
			io.WriteString(w, "alert(1)")
		case "/redirect":
			http.Redirect(w, r, "/page", http.StatusFound)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer upstream.Close()

	p := &Proxy{RequestTimeout: 5 * time.Second}
	base := startProxy(t, p)

	// main page
	status, _, body := httpGet(t, base+"/")
	if status != 200 || !strings.Contains(body, "MortyProxy") {
		t.Fatalf("main page: status=%d", status)
	}

	// proxified html page
	status, headers, body := httpGet(t, base+"/?mortyurl="+url.QueryEscape(upstream.URL+"/page"))
	if status != 200 {
		t.Fatalf("proxified page: status=%d body=%s", status, body)
	}
	if strings.Contains(body, "<script") || strings.Contains(body, "evil") {
		t.Error("script not stripped from proxified page")
	}
	if !strings.Contains(body, "mortyurl=") {
		t.Error("resources not proxified")
	}
	if !strings.Contains(body, "mortyheader") {
		t.Error("morty header not injected")
	}
	if headers.Get("X-Content-Type-Options") != "nosniff" {
		t.Error("nosniff header missing")
	}
	if !strings.Contains(headers.Get("Content-Security-Policy"), "script-src 'none'") {
		t.Error("document CSP missing")
	}

	// attachment forces content-disposition
	status, headers, _ = httpGet(t, base+"/?mortyurl="+url.QueryEscape(upstream.URL+"/doc.pdf"))
	if status != 200 {
		t.Fatalf("pdf: status=%d", status)
	}
	if cd := headers.Get("Content-Disposition"); !strings.HasPrefix(cd, "attachment;") || !strings.Contains(cd, "filename=doc.pdf") {
		t.Errorf("unexpected content-disposition: %q", cd)
	}

	// forbidden content type
	status, _, _ = httpGet(t, base+"/?mortyurl="+url.QueryEscape(upstream.URL+"/secret.js"))
	if status != 403 {
		t.Errorf("forbidden content type: expected 403, got %d", status)
	}

	// redirect without follow: Location rewritten through the proxy
	noRedirectClient := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := noRedirectClient.Get(base + "/?mortyurl=" + url.QueryEscape(upstream.URL+"/redirect"))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close() //nolint:errcheck
	loc := resp.Header.Get("Location")
	if !strings.Contains(loc, "mortyurl=") {
		t.Errorf("redirect location not proxified: %q", loc)
	}

	// healthz and robots.txt
	status, _, body = httpGet(t, base+"/healthz")
	if status != 200 || !strings.Contains(body, "ok") {
		t.Errorf("healthz: status=%d body=%q", status, body)
	}
	status, _, body = httpGet(t, base+"/robots.txt")
	if status != 200 || !strings.Contains(body, "Disallow") {
		t.Errorf("robots.txt: status=%d", status)
	}
}

func TestProxyKeyEnforcement(t *testing.T) {
	key := []byte("morty-test-key")
	p := &Proxy{Key: key, RequestTimeout: 5 * time.Second}
	base := startProxy(t, p)

	// unsigned requests are rejected
	status, _, body := httpGet(t, base+"/?mortyurl="+url.QueryEscape("http://example.com/"))
	if status != 403 || !strings.Contains(body, "mortyhash") {
		t.Errorf("unsigned request: expected 403, got %d", status)
	}

	// tampered hash is rejected
	status, _, _ = httpGet(t, base+"/?mortyhash=deadbeef&mortyurl="+url.QueryEscape("http://example.com/"))
	if status != 403 {
		t.Errorf("tampered hash: expected 403, got %d", status)
	}

	// the warning page is shown when key is configured
	status, _, body = httpGet(t, base+"/")
	if status != 200 || !strings.Contains(body, "does not support direct URL opening") {
		t.Errorf("keyed main page: status=%d", status)
	}
}

var benchSimpleHTML = []byte(`<!doctype html>
<html>
 <head>
  <title>test</title>
 </head>
 <body>
  <h1>Test heading</h1>
 </body>
</html>`)

func BenchmarkSanitizeSimpleHTML(b *testing.B) {
	u, _ := url.Parse("http://127.0.0.1/")
	rc := &RequestConfig{BaseURL: u}
	out := bytes.NewBuffer(nil)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		out.Reset()
		sanitizeHTML(rc, out, benchSimpleHTML)
	}
}

var benchComplexHTML = []byte(`<!doctype html>
<html>
 <head>
  <noscript><meta http-equiv="refresh" content="0; URL=./xy"></noscript>
  <title>test 2</title>
  <script> alert('xy'); </script>
  <link rel="stylesheet" href="./core.bundle.css">
  <style>
   html { background: url(./a.jpg); }
  </style
 </head>
 <body>
  <h1>Test heading</h1>
  <img src="b.png" alt="imgtitle" />
  <form action="/z">
  <input type="submit" style="background: url(http://aa.bb/cc)" >
  </form>
 </body>
</html>`)

func BenchmarkSanitizeComplexHTML(b *testing.B) {
	u, _ := url.Parse("http://127.0.0.1/")
	rc := &RequestConfig{BaseURL: u}
	out := bytes.NewBuffer(nil)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		out.Reset()
		sanitizeHTML(rc, out, benchComplexHTML)
	}
}
