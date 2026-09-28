package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"html/template"
	"io"
	"log/slog"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"golang.org/x/net/html"
)

type sanitizeState int

const (
	stateDefault sanitizeState = iota
	stateInStyle
	stateInNoscript
)

var allowedContentTypeParameters = map[string]bool{
	"charset": true,
}

var unsafeElements = [][]byte{
	[]byte("applet"),
	[]byte("canvas"),
	[]byte("embed"),
	[]byte("math"),
	[]byte("object"),
	[]byte("script"),
	[]byte("svg"),
}

// voidElements cannot have children or end tags in HTML. An unsafe void
// element must be dropped but must not start a blocked section.
var voidElements = [][]byte{
	[]byte("area"),
	[]byte("base"),
	[]byte("br"),
	[]byte("col"),
	[]byte("embed"),
	[]byte("hr"),
	[]byte("img"),
	[]byte("input"),
	[]byte("link"),
	[]byte("meta"),
	[]byte("param"),
	[]byte("source"),
	[]byte("track"),
	[]byte("wbr"),
}

var safeAttributes = [][]byte{
	[]byte("abbr"),
	[]byte("accesskey"),
	[]byte("align"),
	[]byte("alt"),
	[]byte("as"),
	[]byte("autocomplete"),
	[]byte("charset"),
	[]byte("checked"),
	[]byte("class"),
	[]byte("colspan"),
	[]byte("content"),
	[]byte("contenteditable"),
	[]byte("contextmenu"),
	[]byte("controls"),
	[]byte("dir"),
	[]byte("for"),
	[]byte("headers"),
	[]byte("height"),
	[]byte("hidden"),
	[]byte("hreflang"),
	[]byte("id"),
	[]byte("lang"),
	[]byte("media"),
	[]byte("method"),
	[]byte("name"),
	[]byte("nowrap"),
	[]byte("placeholder"),
	[]byte("property"),
	[]byte("rel"),
	[]byte("rowspan"),
	[]byte("scope"),
	[]byte("spellcheck"),
	[]byte("tabindex"),
	[]byte("target"),
	[]byte("title"),
	[]byte("translate"),
	[]byte("type"),
	[]byte("value"),
	[]byte("width"),
}

var linkRelSafeValues = [][]byte{
	[]byte("alternate"),
	[]byte("archives"),
	[]byte("author"),
	[]byte("copyright"),
	[]byte("first"),
	[]byte("help"),
	[]byte("icon"),
	[]byte("index"),
	[]byte("last"),
	[]byte("license"),
	[]byte("manifest"),
	[]byte("next"),
	[]byte("pingback"),
	[]byte("prev"),
	[]byte("publisher"),
	[]byte("search"),
	[]byte("shortcut icon"),
	[]byte("stylesheet"),
	[]byte("up"),
}

var linkHTTPEquivSafeValues = [][]byte{
	// X-UA-Compatible is added automatically, so it can be skipped
	[]byte("date"),
	[]byte("last-modified"),
	[]byte("refresh"), // URL rewrite
	[]byte("content-language"),
}

var cssURLRegexp = regexp.MustCompile("url\\((['\"]?)[ \t\f]*([\t!#-&(*-~]+)(['\"]?)\\)?")

// cssImportRegexp matches the quoted string form of @import:
// @import "x.css" and @import 'x.css' (the url() form is handled by
// cssURLRegexp).
var cssImportRegexp = regexp.MustCompile(`(?i)@import\s+(['"])([^'"]+)['"]`)

// cssImageSetRegexp matches image-set()/ -webkit-image-set() blocks so
// quoted entries inside can be proxified.
var cssImageSetRegexp = regexp.MustCompile(`(?i)(-webkit-)?image-set\(([^)]*)\)`)

// cssQuotedRegexp matches a single quoted string used inside image-set().
var cssQuotedRegexp = regexp.MustCompile(`(['"])([^'"]*)['"]`)

// cssForbiddenRegexp matches legacy CSS code-execution vectors that cannot
// be proxified away: IE expression(), behavior/binding script bindings and
// javascript:/vbscript: URLs. Any hit drops the whole declaration block.
var cssForbiddenRegexp = regexp.MustCompile(`(?i)expression\s*\(|behavior\s*:|-moz-binding|binding\s*:|javascript\s*:|vbscript\s*:`)

type RequestConfig struct {
	Key          []byte
	KeyTTL       int64
	BaseURL      *url.URL
	BodyInjected bool
	signer       *hmacSHA256
}

// hmacSHA256 holds precomputed HMAC-SHA256 key pads so signing each
// proxified link does not rebuild them.
type hmacSHA256 struct {
	ipad [64]byte
	opad [64]byte
}

func newHMACSHA256(key []byte) *hmacSHA256 {
	h := &hmacSHA256{}
	var kb [64]byte
	if len(key) > 64 {
		sum := sha256.Sum256(key)
		copy(kb[:], sum[:])
	} else {
		copy(kb[:], key)
	}
	for i := range kb {
		h.ipad[i] = kb[i] ^ 0x36
		h.opad[i] = kb[i] ^ 0x5c
	}
	return h
}

func (h *hmacSHA256) sum(msg []byte) []byte {
	inner := sha256.New()
	inner.Write(h.ipad[:])
	inner.Write(msg)
	in := inner.Sum(nil)
	outer := sha256.New()
	outer.Write(h.opad[:])
	outer.Write(in)
	return outer.Sum(nil)
}

// hmacString signs msg with the request key, building the precomputed
// pads lazily on first use. RequestConfig is per-request and not shared
// between goroutines, so the lazy init is race free.
func (rc *RequestConfig) hmacString(msg string) string {
	if rc.signer == nil {
		if rc.Key == nil {
			return ""
		}
		rc.signer = newHMACSHA256(rc.Key)
	}
	return hex.EncodeToString(rc.signer.sum([]byte(msg)))
}

// sign produces the mortyhash and optional mortyexp for a signed link.
func (rc *RequestConfig) sign(msg string) (string, string) {
	if rc.KeyTTL > 0 {
		exp := time.Now().Add(time.Duration(rc.KeyTTL) * time.Second).Unix()
		return rc.hmacString(fmt.Sprintf("%s|%d", msg, exp)), strconv.FormatInt(exp, 10)
	}
	return rc.hmacString(msg), ""
}

// htmlAttr is a raw attribute name/value pair from the tokenizer.
type htmlAttr struct {
	name  []byte
	value []byte
}

// writeEscaped writes b escaping the same characters as html.EscapeString:
// & " ' < >
func writeEscaped(out io.Writer, b []byte) {
	last := 0
	for i, c := range b {
		var rep string
		switch c {
		case '&':
			rep = "&amp;"
		case '"':
			rep = "&#34;"
		case '\'':
			rep = "&#39;"
		case '<':
			rep = "&lt;"
		case '>':
			rep = "&gt;"
		default:
			continue
		}
		out.Write(b[last:i])
		io.WriteString(out, rep)
		last = i + 1
	}
	out.Write(b[last:])
}

type htmlBodyExtParam struct {
	BaseURL     string
	HasMortyKey bool
}

type htmlFormExtParam struct {
	BaseURL   string
	MortyHash string
	MortyExp  string
}

var htmlFormExtension *template.Template
var htmlBodyExtension *template.Template

var htmlHeadContentType = `<meta http-equiv="Content-Type" content="text/html; charset=utf-8">
<meta http-equiv="X-UA-Compatible" content="IE=edge">
<meta name="referrer" content="no-referrer">
`

var mortyHTMLPageStart = `<!doctype html>
<html>
<head>
<title>MortyProxy</title>
<meta name="viewport" content="width=device-width, initial-scale=1 , maximum-scale=1.0, user-scalable=1" />
<style>
html { height: 100%; }
body { min-height : 100%; display: flex; flex-direction:column; font-family: 'Garamond', 'Georgia', serif; text-align: center; color: #444; background: #FAFAFA; margin: 0; padding: 0; font-size: 1.1em; }
input { border: 1px solid #888; padding: 0.3em; color: #444; background: #FFF; font-size: 1.1em; }
input[placeholder] { width:80%; }
a { text-decoration: none; #2980b9; }
h1, h2 { font-weight: 200; margin-bottom: 2rem; }
h1 { font-size: 3em; }
.container { flex:1; min-height: 100%; margin-bottom: 1em; }
.footer { margin: 1em; }
.footer p { font-size: 0.8em; }
</style>
</head>
<body>
	<div class="container">
		<h1>MortyProxy</h1>
`

var mortyHTMLPageEnd = `
	</div>
	<div class="footer">
		<p>Morty rewrites web pages to exclude malicious HTML tags and CSS/HTML attributes. It also replaces external resource references to prevent third-party information leaks.<br />
		<a href="https://github.com/asciimoo/morty">view on github</a>
		</p>
	</div>
</body>
</html>`

func init() {
	var err error
	htmlFormExtension, err = template.New("html_form_extension").Parse(
		`<input type="hidden" name="mortyurl" value="{{.BaseURL}}" />{{if .MortyHash}}<input type="hidden" name="mortyhash" value="{{.MortyHash}}" />{{end}}{{if .MortyExp}}<input type="hidden" name="mortyexp" value="{{.MortyExp}}" />{{end}}`)
	if err != nil {
		panic(err)
	}
	htmlBodyExtension, err = template.New("html_body_extension").Parse(`
<input type="checkbox" id="mortytoggle" autocomplete="off" />
<div id="mortyheader">
  <form method="get">
    <label for="mortytoggle">hide</label>
    <span><a href="/">Morty Proxy</a></span>
    <input type="url" value="{{.BaseURL}}" name="mortyurl" {{if .HasMortyKey }}readonly="true"{{end}} />
    This is a <a href="https://github.com/asciimoo/morty">proxified and sanitized</a> view of the page, visit <a href="{{.BaseURL}}" rel="noreferrer">original site</a>.
  </form>
</div>
<style>
body{ position: absolute !important; top: 42px !important; left: 0 !important; right: 0 !important; bottom: 0 !important; }
#mortyheader { position: fixed; margin: 0; box-sizing: border-box; -webkit-box-sizing: border-box; top: 0; left: 0; right: 0; z-index: 2147483647 !important; font-size: 12px; line-height: normal; border-width: 0px 0px 2px 0; border-style: solid; border-color: #AAAAAA; background: #FFF; padding: 4px; color: #444; height: 42px; }
#mortyheader * { padding: 0; margin: 0; }
#mortyheader p { padding: 0 0 0.7em 0; display: block; }
#mortyheader a { color: #3498db; font-weight: bold; display: inline; }
#mortyheader label { text-align: right; cursor: pointer; position: fixed; right: 4px; top: 4px; display: block; color: #444; }
#mortyheader > form > span { font-size: 24px; font-weight: bold; margin-right: 20px; margin-left: 20px; }
input[type=checkbox]#mortytoggle { display: none; }
input[type=checkbox]#mortytoggle:checked ~ div { display: none; visibility: hidden; }
#mortyheader input[type=url] { width: 50%; padding: 4px; font-size: 16px; }
</style>
`)
	if err != nil {
		panic(err)
	}
}

func sanitizeCSS(rc *RequestConfig, out io.Writer, css []byte) {
	// drop stylesheets carrying script-execution vectors outright
	if cssForbiddenRegexp.Match(css) {
		slog.Debug("css dropped: forbidden construct")
		return
	}

	// rewrite @import "..." and image-set("...") string forms first;
	// url(...) is handled afterwards by cssURLRegexp
	css = rewriteCSSQuoted(rc, css, cssImportRegexp)
	css = rewriteCSSImageSets(rc, css)

	urlSlices := cssURLRegexp.FindAllSubmatchIndex(css, -1)

	if urlSlices == nil {
		out.Write(css)
		return
	}

	startIndex := 0

	for _, s := range urlSlices {
		urlStart := s[4]
		urlEnd := s[5]

		if uri, err := rc.ProxifyURI(css[urlStart:urlEnd]); err == nil {
			out.Write(css[startIndex:urlStart])
			out.Write([]byte(uri))
			startIndex = urlEnd
		} else {
			slog.Debug("cannot proxify css uri", "uri", string(css[urlStart:urlEnd]))
		}
	}
	if startIndex < len(css) {
		out.Write(css[startIndex:])
	}
}

// rewriteCSSQuoted rewrites the URL inside each match of re, where the
// second capture group holds the raw URL.
func rewriteCSSQuoted(rc *RequestConfig, css []byte, re *regexp.Regexp) []byte {
	var buf bytes.Buffer
	start := 0
	for _, m := range re.FindAllSubmatchIndex(css, -1) {
		buf.Write(css[start:m[2]])
		buf.Write(css[m[2]:m[3]])
		if uri, err := rc.ProxifyURI(css[m[4]:m[5]]); err == nil {
			buf.WriteString(uri)
		} else {
			buf.Write(css[m[4]:m[5]])
		}
		buf.Write(css[m[2]:m[3]])
		start = m[1]
	}
	buf.Write(css[start:])
	return buf.Bytes()
}

// rewriteCSSImageSets proxifies quoted entries inside image-set() /
// -webkit-image-set() blocks. Unquoted and url() entries are left for
// the url() pass.
func rewriteCSSImageSets(rc *RequestConfig, css []byte) []byte {
	var buf bytes.Buffer
	start := 0
	for _, m := range cssImageSetRegexp.FindAllSubmatchIndex(css, -1) {
		inner := rewriteCSSQuoted(rc, css[m[4]:m[5]], cssQuotedRegexp)
		buf.Write(css[start:m[4]])
		buf.Write(inner)
		buf.Write(css[m[5]:m[1]])
		start = m[1]
	}
	buf.Write(css[start:])
	return buf.Bytes()
}

func sanitizeHTML(rc *RequestConfig, out io.Writer, htmlDoc []byte) {
	r := bytes.NewReader(htmlDoc)
	decoder := html.NewTokenizer(r)
	decoder.AllowCDATA(true)

	var blockedElements [][]byte
	state := stateDefault
	for {
		token := decoder.Next()
		if token == html.ErrorToken {
			if err := decoder.Err(); err != io.EOF {
				slog.Debug("failed to parse HTML", "err", decoder.Err())
			}
			break
		}

		if len(blockedElements) == 0 {

			switch token {
			case html.StartTagToken, html.SelfClosingTagToken:
				tag, hasAttrs := decoder.TagName()
				if inArray(tag, unsafeElements) {
					if token == html.StartTagToken && !inArray(tag, voidElements) {
						// tag names from the tokenizer are only valid
						// until the next token, so they must be copied
						unsafeTag := make([]byte, len(tag))
						copy(unsafeTag, tag)
						blockedElements = append(blockedElements, unsafeTag)
					}
					break
				}
				if bytes.Equal(tag, []byte("base")) {
					for {
						attrName, attrValue, moreAttr := decoder.TagAttr()
						if bytes.Equal(attrName, []byte("href")) {
							if parsedURI, err := rc.BaseURL.Parse(string(attrValue)); err == nil {
								rc.BaseURL = parsedURI
							}
						}
						if !moreAttr {
							break
						}
					}
					break
				}
				if bytes.Equal(tag, []byte("noscript")) {
					state = stateInNoscript
					break
				}

				if bytes.Equal(tag, []byte("link")) || bytes.Equal(tag, []byte("meta")) {
					var attrs []htmlAttr
					if hasAttrs {
						for {
							attrName, attrValue, moreAttr := decoder.TagAttr()
							attrs = append(attrs, htmlAttr{attrName, attrValue})
							if !moreAttr {
								break
							}
						}
					}
					if bytes.Equal(tag, []byte("link")) {
						sanitizeLinkTag(rc, out, attrs)
					} else {
						sanitizeMetaTag(rc, out, attrs)
					}
					break
				}

				out.Write([]byte{'<'})
				out.Write(tag)

				// the form action is captured while streaming attributes
				// so the hidden inputs below point at the right target
				var formURL *url.URL
				if bytes.Equal(tag, []byte("form")) {
					formURL = rc.BaseURL
				}
				if hasAttrs {
					for {
						attrName, attrValue, moreAttr := decoder.TagAttr()
						if formURL != nil && bytes.Equal(attrName, []byte("action")) {
							if parsed, err := rc.BaseURL.Parse(string(attrValue)); err == nil {
								formURL = parsed
							}
						}
						sanitizeAttr(rc, out, attrName, attrValue)
						if !moreAttr {
							break
						}
					}
				}

				if token == html.SelfClosingTagToken {
					io.WriteString(out, " />")
				} else {
					io.WriteString(out, ">")
					if bytes.Equal(tag, []byte("style")) {
						state = stateInStyle
					}
				}

				if bytes.Equal(tag, []byte("head")) {
					io.WriteString(out, htmlHeadContentType)
				}

				if formURL != nil {
					urlStr := formURL.String()
					var key, exp string
					if rc.Key != nil {
						key, exp = rc.sign(urlStr)
					}
					if err := htmlFormExtension.Execute(out, htmlFormExtParam{urlStr, key, exp}); err != nil {
						slog.Debug("failed to inject form extension", "err", err)
					}
				}

			case html.EndTagToken:
				tag, _ := decoder.TagName()
				writeEndTag := true
				switch string(tag) {
				case "body":
					param := htmlBodyExtParam{rc.BaseURL.String(), false}
					if len(rc.Key) > 0 {
						param.HasMortyKey = true
					}
					if err := htmlBodyExtension.Execute(out, param); err != nil {
						slog.Debug("failed to inject body extension", "err", err)
					}
					rc.BodyInjected = true
				case "style":
					state = stateDefault
				case "noscript":
					state = stateDefault
					writeEndTag = false
				}
				// skip noscript tags - only the tag, not the content, because javascript is sanitized
				if writeEndTag {
					out.Write([]byte("</"))
					out.Write(tag)
					out.Write([]byte{'>'})
				}

			case html.TextToken:
				switch state {
				case stateDefault:
					out.Write(decoder.Raw())
				case stateInStyle:
					sanitizeCSS(rc, out, decoder.Raw())
				case stateInNoscript:
					sanitizeHTML(rc, out, decoder.Raw())
				}

			case html.CommentToken:
				// ignore comment. TODO : parse IE conditional comment

			case html.DoctypeToken:
				out.Write(decoder.Raw())
			}
		} else {
			switch token {
			case html.StartTagToken:
				tag, _ := decoder.TagName()
				if inArray(tag, unsafeElements) && !inArray(tag, voidElements) {
					unsafeTag := make([]byte, len(tag))
					copy(unsafeTag, tag)
					blockedElements = append(blockedElements, unsafeTag)
				}

			case html.EndTagToken:
				tag, _ := decoder.TagName()
				if bytes.Equal(blockedElements[len(blockedElements)-1], tag) {
					blockedElements = blockedElements[:len(blockedElements)-1]
				}
			}
		}
	}
}

func sanitizeLinkTag(rc *RequestConfig, out io.Writer, attrs []htmlAttr) {
	exclude := false
	for _, attr := range attrs {
		if bytes.Equal(attr.name, []byte("rel")) && !inArray(attr.value, linkRelSafeValues) {
			exclude = true
			break
		}
		if bytes.Equal(attr.name, []byte("as")) && bytes.Equal(attr.value, []byte("script")) {
			exclude = true
			break
		}
	}

	if !exclude {
		out.Write([]byte("<link"))
		for _, attr := range attrs {
			sanitizeAttr(rc, out, attr.name, attr.value)
		}
		out.Write([]byte(">"))
	}
}

func sanitizeMetaTag(rc *RequestConfig, out io.Writer, attrs []htmlAttr) {
	var httpEquiv []byte
	var content []byte

	for _, attr := range attrs {
		if bytes.Equal(attr.name, []byte("http-equiv")) {
			httpEquiv = bytes.ToLower(attr.value)
			// exclude some <meta http-equiv="..." ..>
			if !inArray(httpEquiv, linkHTTPEquivSafeValues) {
				return
			}
		}
		if bytes.Equal(attr.name, []byte("content")) {
			content = attr.value
		}
		if bytes.Equal(attr.name, []byte("charset")) {
			// exclude <meta charset="...">
			return
		}
	}

	out.Write([]byte("<meta"))
	urlIndex := bytes.Index(bytes.ToLower(content), []byte("url="))
	if bytes.Equal(httpEquiv, []byte("refresh")) && urlIndex != -1 {
		contentURL := content[urlIndex+4:]
		// special case of <meta http-equiv="refresh" content="0; url='example.com/url.with.quote.outside'">
		if len(contentURL) >= 2 && (contentURL[0] == '\'' || contentURL[0] == '"') {
			if contentURL[0] == contentURL[len(contentURL)-1] {
				contentURL = contentURL[1 : len(contentURL)-1]
			}
		}
		// output proxify result
		if uri, err := rc.ProxifyURI(contentURL); err == nil {
			out.Write([]byte(` http-equiv="refresh" content="`))
			writeEscaped(out, content[:urlIndex])
			out.Write([]byte("url="))
			writeEscaped(out, []byte(uri))
			out.Write([]byte{'"'})
		}
	} else {
		if len(httpEquiv) > 0 {
			out.Write([]byte(` http-equiv="`))
			writeEscaped(out, httpEquiv)
			out.Write([]byte{'"'})
		}
		for _, attr := range attrs {
			sanitizeAttr(rc, out, attr.name, attr.value)
		}
	}
	out.Write([]byte(">"))
}

func sanitizeAttr(rc *RequestConfig, out io.Writer, attrName, attrValue []byte) {
	writeAttr := func(value []byte) {
		out.Write([]byte{' '})
		out.Write(attrName)
		out.Write([]byte{'=', '"'})
		writeEscaped(out, value)
		out.Write([]byte{'"'})
	}
	if inArray(attrName, safeAttributes) {
		writeAttr(attrValue)
		return
	}
	switch string(attrName) {
	case "src", "href", "action", "formaction", "poster", "cite", "background", "longdesc", "usemap":
		if uri, err := rc.ProxifyURI(attrValue); err == nil {
			writeAttr([]byte(uri))
		} else {
			slog.Debug("cannot proxify uri", "uri", string(attrValue))
		}
	case "srcdoc":
		// iframe srcdoc carries a full inline HTML document
		doc := html.UnescapeString(string(attrValue))
		var buf bytes.Buffer
		injected := rc.BodyInjected
		sanitizeHTML(rc, &buf, []byte(doc))
		rc.BodyInjected = injected
		writeAttr(buf.Bytes())
	case "srcset":
		writeAttr([]byte(proxifySrcSet(rc, attrValue)))
	case "style":
		cssAttr := bytes.NewBuffer(nil)
		sanitizeCSS(rc, cssAttr, attrValue)
		writeAttr(cssAttr.Bytes())
	}
}

// proxifySrcSet rewrites every URL in a srcset attribute value.
// A srcset entry is "url descriptor1, descriptor2" separated by commas.
func proxifySrcSet(rc *RequestConfig, value []byte) string {
	var b strings.Builder
	b.Grow(len(value) + 32)
	first := true
	for len(value) > 0 {
		var entry []byte
		if i := bytes.IndexByte(value, ','); i >= 0 {
			entry, value = value[:i], value[i+1:]
		} else {
			entry, value = value, nil
		}
		entry = bytes.TrimSpace(entry)
		if len(entry) == 0 {
			continue
		}
		// split entry into url and trailing descriptors
		u := entry
		var rest []byte
		if i := bytes.IndexAny(entry, " \t\f\r\n"); i >= 0 {
			u, rest = entry[:i], entry[i:]
		}
		if !first {
			b.WriteString(", ")
		}
		first = false
		if uri, err := rc.ProxifyURI(u); err == nil {
			b.WriteString(uri)
		} else {
			b.Write(u)
		}
		if rest != nil {
			b.Write(rest)
		}
	}
	return b.String()
}

func mergeURIs(u1, u2 *url.URL) *url.URL {
	if u2 == nil {
		return u1
	}
	return u1.ResolveReference(u2)
}

// sanitizeURI removes all runes below 32 (included) at the beginning and
// end of the URI, and lower cases the scheme.
// It avoids memory allocation except for the scheme.
func sanitizeURI(uri []byte) ([]byte, string) {
	firstRuneIndex := 0
	firstRuneSeen := false
	schemeLastIndex := -1
	buffer := bytes.NewBuffer(make([]byte, 0, 10))

	// remove trailing space and special characters
	uri = bytes.TrimRight(uri, "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1A\x1B\x1C\x1D\x1E\x1F\x20")

	// loop over byte by byte
	for i, c := range uri {
		// ignore special characters and space (c <= 32)
		if c > 32 {
			// append the lower case rune to the buffer
			if c < utf8.RuneSelf && 'A' <= c && c <= 'Z' {
				c = c + 'a' - 'A'
			}

			buffer.WriteByte(c)

			// update the first rune index that is not a special rune
			if !firstRuneSeen {
				firstRuneIndex = i
				firstRuneSeen = true
			}

			if c == ':' {
				// colon found, we have found the scheme
				schemeLastIndex = i
				break
			} else if c == '/' || c == '?' || c == '\\' || c == '#' {
				// special case : most probably a relative URI
				break
			}
		}
	}

	if schemeLastIndex != -1 {
		// scheme found
		// copy the "lower case without special runes scheme" before the ":" rune
		schemeStartIndex := schemeLastIndex - buffer.Len() + 1
		copy(uri[schemeStartIndex:], buffer.Bytes())
		// and return the result
		return uri[schemeStartIndex:], buffer.String()
	}
	// scheme NOT found
	return uri[firstRuneIndex:], ""
}

func (rc *RequestConfig) ProxifyURI(uri []byte) (string, error) {
	// sanitize URI
	uri, scheme := sanitizeURI(uri)

	// remove dangerous schemes
	switch scheme {
	case "javascript:", "vbscript:":
		return "", nil
	case "data:":
		if bytes.HasPrefix(uri, []byte("data:image/png;")) ||
			bytes.HasPrefix(uri, []byte("data:image/jpeg;")) ||
			bytes.HasPrefix(uri, []byte("data:image/pjpeg;")) ||
			bytes.HasPrefix(uri, []byte("data:image/gif;")) ||
			bytes.HasPrefix(uri, []byte("data:image/webp;")) ||
			bytes.HasPrefix(uri, []byte("data:image/avif;")) {
			// should be safe
			return string(uri), nil
		}
		// unsafe data
		return "", nil
	}

	// parse the uri
	u, err := url.Parse(string(uri))
	if err != nil {
		return "", err
	}

	// get the fragment (with the prefix "#")
	fragment := ""
	if len(u.Fragment) > 0 {
		fragment = "#" + u.Fragment
	}

	// reset the fragment: it is not included in the mortyurl
	u.Fragment = ""

	// merge the URI with the document URI
	u = mergeURIs(rc.BaseURL, u)

	// simple internal link ?
	// some web pages describe the whole link https://same:auth@same.host/same.path?same.query#new.fragment
	if u.Scheme == rc.BaseURL.Scheme &&
		(rc.BaseURL.User == nil || (u.User != nil && u.User.String() == rc.BaseURL.User.String())) &&
		u.Host == rc.BaseURL.Host &&
		u.Path == rc.BaseURL.Path &&
		u.RawQuery == rc.BaseURL.RawQuery {
		// the fragment is the only difference between the document URI and the uri parameter
		return fragment, nil
	}

	// return full URI and fragment (if not empty)
	mortyURI := u.String()

	var b strings.Builder
	b.Grow(len(mortyURI) + 96)
	b.WriteString("./?")
	if rc.Key == nil {
		b.WriteString("mortyurl=")
	} else {
		h, exp := rc.sign(mortyURI)
		b.WriteString("mortyhash=")
		b.WriteString(h)
		if exp != "" {
			b.WriteString("&mortyexp=")
			b.WriteString(exp)
		}
		b.WriteString("&mortyurl=")
	}
	b.WriteString(url.QueryEscape(mortyURI))
	b.WriteString(fragment)
	return b.String(), nil
}

func inArray(b []byte, a [][]byte) bool {
	for _, b2 := range a {
		if bytes.Equal(b, b2) {
			return true
		}
	}
	return false
}
