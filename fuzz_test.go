package main

import (
	"bytes"
	"net/url"
	"testing"
)

func FuzzSanitizeHTML(f *testing.F) {
	seeds := [][]byte{
		[]byte("<html><body><p>ok</p></body></html>"),
		[]byte("<script>alert(1)</script><noscript><a href=x>y</a></noscript>"),
		[]byte("<style>a{background:url(b.png)}</style><meta http-equiv=refresh content=\"0;url=/x\">"),
		[]byte("<form action=/f><input name=q></form><iframe srcdoc=\"&lt;p&gt;"),
		[]byte("<a href='jav\tascript:alert(1)' srcset='/a.png 1x, /b.png 2x'>"),
		[]byte(""),
	}
	for _, s := range seeds {
		f.Add(s)
	}
	u, _ := url.Parse("http://base.example/")
	f.Fuzz(func(t *testing.T, data []byte) {
		rc := &RequestConfig{BaseURL: u, Key: []byte("k")}
		out := bytes.NewBuffer(nil)
		sanitizeHTML(rc, out, data)
	})
}

func FuzzSanitizeURI(f *testing.F) {
	seeds := []string{
		"https://example.com/",
		"   javascript:alert(1)   ",
		"data:image/png;base64,AAAA",
		"\x00\x01weird://thing",
		"Ht  TP://Example.COM/path?q=1#f",
		"",
		":",
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		sanitizeURI([]byte(s))
	})
}

func FuzzProxifyURI(f *testing.F) {
	seeds := []string{
		"http://x.com/a",
		"./rel/../p",
		"//proto-rel/x",
		"#frag",
		"javascript:void(0)",
		"data:text/html;base64,AAA",
		"",
	}
	for _, s := range seeds {
		f.Add(s)
	}
	u, _ := url.Parse("http://base.example/dir/page?q=1")
	f.Fuzz(func(t *testing.T, s string) {
		rc := &RequestConfig{BaseURL: u, Key: []byte("k"), KeyTTL: 60}
		out, err := rc.ProxifyURI([]byte(s))
		if err == nil && out != "" && out[0] != '/' && out[0] != '#' && out[0] != '.' && out[:2] != "./" && !bytes.HasPrefix([]byte(out), []byte("data:image/")) {
			t.Errorf("unexpected proxified output %q for %q", out, s)
		}
	})
}

func FuzzProxifySrcSet(f *testing.F) {
	seeds := []string{
		"/a.png 1x, /b.png 2x",
		"a.png 480w, b.png 800w",
		"   ",
		",,,",
	}
	for _, s := range seeds {
		f.Add(s)
	}
	u, _ := url.Parse("http://base.example/")
	f.Fuzz(func(t *testing.T, s string) {
		rc := &RequestConfig{BaseURL: u}
		proxifySrcSet(rc, []byte(s))
	})
}

func FuzzSanitizeCSS(f *testing.F) {
	seeds := [][]byte{
		[]byte(`a{background:url("b.png")}`),
		[]byte(`@import "x.css"; body{color:red}`),
		[]byte(`a{background:image-set("a.png" 1x,'b.png' 2x)}`),
		[]byte(`a{background:url(javascript:alert(1))}`),
		[]byte(""),
	}
	for _, s := range seeds {
		f.Add(s)
	}
	u, _ := url.Parse("http://base.example/")
	f.Fuzz(func(t *testing.T, data []byte) {
		rc := &RequestConfig{BaseURL: u}
		out := bytes.NewBuffer(nil)
		sanitizeCSS(rc, out, data)
	})
}

func FuzzVerifySignedURI(f *testing.F) {
	key := []byte("k")
	uri := []byte("https://example.com/")
	h, exp := signURL(string(uri), key, 60)
	f.Add(uri, []byte(h), []byte(exp))
	f.Add([]byte("x"), []byte("deadbeef"), []byte("9999999999"))
	f.Add([]byte{}, []byte{}, []byte{})
	f.Fuzz(func(t *testing.T, u, hashB, expB []byte) {
		verifySignedURI(u, hashB, expB, key, 60)
		verifySignedURI(u, hashB, nil, key, 0)
	})
}
