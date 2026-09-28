package main

import (
	"bytes"
	"fmt"
	"net/url"
	"strings"
	"testing"
)

var benchHTML []byte

func init() {
	var b strings.Builder
	b.WriteString(`<!doctype html><html><head><title>t</title>`)
	b.WriteString(`<style>a{background:url("/css/x.png")}</style></head><body>`)
	for i := 0; i < 300; i++ {
		fmt.Fprintf(&b, `<div class="row" id="r%d"><a href="/link/%d?x=1&amp;y=2">link %d</a>`+
			`<img src="/img/%d.png" srcset="/img/%d.png 1x, /img/%d@2x.png 2x" style="border:0">`+
			`<p title="text &quot;quoted&quot;">paragraph %d &amp; more</p></div>`,
			i, i, i, i, i, i, i)
	}
	b.WriteString(`</body></html>`)
	benchHTML = []byte(b.String())
}

func benchRC() *RequestConfig {
	u, _ := url.Parse("https://upstream.example/dir/page?q=1")
	return &RequestConfig{BaseURL: u, Key: []byte("0123456789abcdef")}
}

func BenchmarkSanitizeHTML(b *testing.B) {
	rc := benchRC()
	out := bytes.NewBuffer(make([]byte, 0, len(benchHTML)*3))
	b.ReportAllocs()
	b.SetBytes(int64(len(benchHTML)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		out.Reset()
		rc.BodyInjected = false
		sanitizeHTML(rc, out, benchHTML)
	}
}

func BenchmarkSanitizeCSS(b *testing.B) {
	rc := benchRC()
	css := []byte(strings.Repeat(
		`a{background:url("/img/a.png");margin:0}`+
			`@import "theme.css";`+
			`div{list-style-image:-webkit-image-set("i.png" 1x,'j.png' 2x)}`, 50))
	out := bytes.NewBuffer(make([]byte, 0, len(css)*2))
	b.ReportAllocs()
	b.SetBytes(int64(len(css)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		out.Reset()
		sanitizeCSS(rc, out, css)
	}
}

func BenchmarkProxifyURI(b *testing.B) {
	rc := benchRC()
	uri := []byte("../deep/path/image.png?size=2#top")
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := rc.ProxifyURI(uri); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkProxifySrcSet(b *testing.B) {
	rc := benchRC()
	v := []byte("/a.png 1x, /b.png 2x, /c.png 3x")
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		proxifySrcSet(rc, v)
	}
}

func BenchmarkVerifySignedURI(b *testing.B) {
	key := []byte("0123456789abcdef")
	uri := []byte("https://example.com/x?q=1")
	h := []byte(hash(string(uri), key))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		verifySignedURI(uri, h, nil, key, 0)
	}
}

func BenchmarkSanitizeURI(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		sanitizeURI([]byte("  HTTP://Example.COM/path?q=1#f"))
	}
}

func BenchmarkHash(b *testing.B) {
	key := []byte("0123456789abcdef")
	msg := "https://example.com/x?q=1"
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		hash(msg, key)
	}
}
