package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"html/template"
	"io"
	"log"
	"mime"
	"net"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"
	"unicode/utf8"

	"github.com/valyala/fasthttp"
	"github.com/valyala/fasthttp/fasthttpproxy"
	"golang.org/x/net/html"
	"golang.org/x/net/html/charset"
	"golang.org/x/text/encoding"

	"github.com/asciimoo/morty/config"
	"github.com/asciimoo/morty/contenttype"
)

type sanitizeState int

const (
	stateDefault sanitizeState = iota
	stateInStyle
	stateInNoscript
)

const version = "v0.3.0"

const maxRedirectCount = 5

var client = &fasthttp.Client{
	MaxResponseBodySize: 10 * 1024 * 1024, // 10M
	ReadBufferSize:      16 * 1024,        // 16K
}

var cfg = config.DefaultConfig

var allowedContentTypeFilter = contenttype.NewFilterOr([]contenttype.Filter{
	// html
	contenttype.NewFilterEquals("text", "html", ""),
	contenttype.NewFilterEquals("application", "xhtml", "xml"),
	// css
	contenttype.NewFilterEquals("text", "css", ""),
	// images
	contenttype.NewFilterEquals("image", "gif", ""),
	contenttype.NewFilterEquals("image", "png", ""),
	contenttype.NewFilterEquals("image", "jpeg", ""),
	contenttype.NewFilterEquals("image", "pjpeg", ""),
	contenttype.NewFilterEquals("image", "webp", ""),
	contenttype.NewFilterEquals("image", "avif", ""),
	contenttype.NewFilterEquals("image", "svg+xml", ""),
	contenttype.NewFilterEquals("image", "tiff", ""),
	contenttype.NewFilterEquals("image", "vnd.microsoft.icon", ""),
	contenttype.NewFilterEquals("image", "bmp", ""),
	contenttype.NewFilterEquals("image", "x-ms-bmp", ""),
	contenttype.NewFilterEquals("image", "x-icon", ""),
	// fonts
	contenttype.NewFilterEquals("font", "otf", ""),
	contenttype.NewFilterEquals("font", "ttf", ""),
	contenttype.NewFilterEquals("font", "woff", ""),
	contenttype.NewFilterEquals("font", "woff2", ""),
	contenttype.NewFilterEquals("application", "font-otf", ""),
	contenttype.NewFilterEquals("application", "font-ttf", ""),
	contenttype.NewFilterEquals("application", "font-woff", ""),
	contenttype.NewFilterEquals("application", "vnd.ms-fontobject", ""),
	// audio/video
	contenttype.NewFilterEquals("audio", "mpeg", ""),
	contenttype.NewFilterEquals("audio", "ogg", ""),
	contenttype.NewFilterEquals("video", "mp4", ""),
	contenttype.NewFilterEquals("video", "webm", ""),
})

var allowedContentTypeAttachmentFilter = contenttype.NewFilterOr([]contenttype.Filter{
	// texts
	contenttype.NewFilterEquals("text", "csv", ""),
	contenttype.NewFilterEquals("text", "tab-separated-values", ""),
	contenttype.NewFilterEquals("text", "plain", ""),
	// API
	contenttype.NewFilterEquals("application", "json", ""),
	// Documents
	contenttype.NewFilterEquals("application", "x-latex", ""),
	contenttype.NewFilterEquals("application", "pdf", ""),
	contenttype.NewFilterEquals("application", "vnd.oasis.opendocument.text", ""),
	contenttype.NewFilterEquals("application", "vnd.oasis.opendocument.spreadsheet", ""),
	contenttype.NewFilterEquals("application", "vnd.oasis.opendocument.presentation", ""),
	contenttype.NewFilterEquals("application", "vnd.oasis.opendocument.graphics", ""),
	// Compressed archives
	contenttype.NewFilterEquals("application", "zip", ""),
	contenttype.NewFilterEquals("application", "gzip", ""),
	contenttype.NewFilterEquals("application", "x-compressed", ""),
	contenttype.NewFilterEquals("application", "x-gtar", ""),
	contenttype.NewFilterEquals("application", "x-compress", ""),
	// Generic binary
	contenttype.NewFilterEquals("application", "octet-stream", ""),
})

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
	[]byte("poster"),
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

var cssURLRegexp = regexp.MustCompile("url\\((['\"]?)[ \t\f]*([	!#-&(*-~]+)(['\"]?)\\)?")

// documentCSP is applied to proxified HTML pages: JavaScript is always
// disabled, other resources are allowed because every reference is
// rewritten to same-origin proxified URLs.
const documentCSP = "default-src 'none'; script-src 'none'; img-src 'self' data:; media-src 'self'; style-src 'self' 'unsafe-inline'; font-src 'self' data:; form-action 'self'; frame-src 'self'; base-uri 'none'"

// pageCSP is applied to pages generated by morty itself.
const pageCSP = "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'"

type Proxy struct {
	Key            []byte
	RequestTimeout time.Duration
	FollowRedirect bool
}

type RequestConfig struct {
	Key          []byte
	BaseURL      *url.URL
	BodyInjected bool
}

type htmlBodyExtParam struct {
	BaseURL     string
	HasMortyKey bool
}

type htmlFormExtParam struct {
	BaseURL   string
	MortyHash string
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

var faviconBytes []byte

func init() {
	faviconBase64 := "iVBORw0KGgoAAAANSUhEUgAAABAAAAAQEAYAAABPYyMiAAAABmJLR0T///////8JWPfcAAAACXBIWXMAAABIAAAASABGyWs+AAAAF0lEQVRIx2NgGAWjYBSMglEwCkbBSAcACBAAAeaR9cIAAAAASUVORK5CYII"

	faviconBytes, _ = base64.StdEncoding.DecodeString(faviconBase64)
	var err error
	htmlFormExtension, err = template.New("html_form_extension").Parse(
		`<input type="hidden" name="mortyurl" value="{{.BaseURL}}" />{{if .MortyHash}}<input type="hidden" name="mortyhash" value="{{.MortyHash}}" />{{end}}`)
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

// setSecurityHeaders adds headers applied to every response.
func setSecurityHeaders(ctx *fasthttp.RequestCtx, csp string) {
	ctx.Response.Header.Set("X-Content-Type-Options", "nosniff")
	ctx.Response.Header.Set("Referrer-Policy", "no-referrer")
	ctx.Response.Header.Set("X-Robots-Tag", "noindex, nofollow")
	if csp != "" {
		ctx.Response.Header.Set("Content-Security-Policy", csp)
	}
}

func (p *Proxy) RequestHandler(ctx *fasthttp.RequestCtx) {
	if appRequestHandler(ctx) {
		return
	}

	requestHash := popRequestParam(ctx, []byte("mortyhash"))

	requestURI := popRequestParam(ctx, []byte("mortyurl"))

	if requestURI == nil {
		p.serveMainPage(ctx, fasthttp.StatusOK, nil)
		return
	}

	if p.Key != nil {
		if !verifyRequestURI(requestURI, requestHash, p.Key) {
			// HTTP status code 403 : Forbidden
			p.serveMainPage(ctx, fasthttp.StatusForbidden, errors.New(`invalid "mortyhash" parameter`))
			return
		}
	}

	requestURIQuery := ctx.QueryArgs().QueryString()
	if len(requestURIQuery) > 0 {
		if bytes.ContainsRune(requestURI, '?') {
			requestURI = append(requestURI, '&')
		} else {
			requestURI = append(requestURI, '?')
		}
		requestURI = append(requestURI, requestURIQuery...)
	}

	p.ProcessURI(ctx, string(requestURI), 0)
}

func (p *Proxy) ProcessURI(ctx *fasthttp.RequestCtx, requestURIStr string, redirectCount int) {
	parsedURI, err := url.Parse(requestURIStr)

	if err != nil {
		// HTTP status code 500 : Internal Server Error
		p.serveMainPage(ctx, fasthttp.StatusInternalServerError, err)
		return
	}

	if parsedURI.Scheme == "" {
		requestURIStr = "https://" + requestURIStr
		parsedURI, err = url.Parse(requestURIStr)
		if err != nil {
			p.serveMainPage(ctx, fasthttp.StatusInternalServerError, err)
			return
		}
	}

	// Serve an intermediate page for protocols other than HTTP(S)
	if (parsedURI.Scheme != "http" && parsedURI.Scheme != "https") || strings.HasSuffix(parsedURI.Host, ".onion") {
		p.serveExitMortyPage(ctx, parsedURI)
		return
	}

	req := fasthttp.AcquireRequest()
	defer fasthttp.ReleaseRequest(req)
	req.SetConnectionClose()

	if cfg.Debug {
		log.Println(string(ctx.Method()), requestURIStr)
	}

	req.SetRequestURI(requestURIStr)
	req.Header.SetUserAgentBytes([]byte("Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0"))

	resp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseResponse(resp)

	req.Header.SetMethodBytes(ctx.Method())
	if ctx.IsPost() || ctx.IsPut() {
		req.SetBody(ctx.PostBody())
		if contentType := ctx.Request.Header.ContentType(); len(contentType) > 0 {
			req.Header.SetContentTypeBytes(contentType)
		}
	}

	err = client.DoTimeout(req, resp, p.RequestTimeout)

	if err != nil {
		if errors.Is(err, fasthttp.ErrTimeout) {
			// HTTP status code 504 : Gateway Time-Out
			p.serveMainPage(ctx, fasthttp.StatusGatewayTimeout, err)
		} else {
			// HTTP status code 500 : Internal Server Error
			p.serveMainPage(ctx, fasthttp.StatusInternalServerError, err)
		}
		return
	}

	if resp.StatusCode() != fasthttp.StatusOK {
		switch resp.StatusCode() {
		case fasthttp.StatusMovedPermanently,
			fasthttp.StatusFound,
			fasthttp.StatusSeeOther,
			fasthttp.StatusTemporaryRedirect,
			fasthttp.StatusPermanentRedirect:
			loc := resp.Header.Peek("Location")
			if loc != nil {
				if p.FollowRedirect && ctx.IsGet() {
					// GET method: Morty follows the redirect
					if redirectCount < maxRedirectCount {
						if cfg.Debug {
							log.Println("follow redirect to", string(loc))
						}
						// resolve relative redirect targets against the current URI
						nextURI, resolveErr := parsedURI.Parse(string(loc))
						if resolveErr != nil {
							p.serveMainPage(ctx, fasthttp.StatusInternalServerError, resolveErr)
							return
						}
						p.ProcessURI(ctx, nextURI.String(), redirectCount+1)
					} else {
						p.serveMainPage(ctx, fasthttp.StatusPermanentRedirect, errors.New("too many redirects"))
					}
					return
				}
				// Other HTTP methods: Morty does NOT follow the redirect
				rc := &RequestConfig{Key: p.Key, BaseURL: parsedURI}
				proxifiedURL, err := rc.ProxifyURI(loc)
				if err == nil {
					ctx.SetStatusCode(resp.StatusCode())
					ctx.Response.Header.Add("Location", proxifiedURL)
					if cfg.Debug {
						log.Println("redirect to", string(loc))
					}
					return
				}
			}
		}
		p.serveMainPage(ctx, resp.StatusCode(), fmt.Errorf("invalid response: %d (%s)", resp.StatusCode(), requestURIStr))
		return
	}

	contentTypeBytes := resp.Header.Peek("Content-Type")

	if contentTypeBytes == nil {
		// HTTP status code 503 : Service Unavailable
		p.serveMainPage(ctx, fasthttp.StatusServiceUnavailable, errors.New("invalid content type"))
		return
	}

	contentTypeString := string(contentTypeBytes)

	// decode Content-Type header
	contentType, err := contenttype.ParseContentType(contentTypeString)
	if err != nil {
		// HTTP status code 503 : Service Unavailable
		p.serveMainPage(ctx, fasthttp.StatusServiceUnavailable, errors.New("invalid content type"))
		return
	}

	// content-disposition of the upstream response
	contentDispositionBytes := resp.Header.Peek("Content-Disposition")

	// check content type
	if !allowedContentTypeFilter(contentType) {
		// it is not a usual content type
		if allowedContentTypeAttachmentFilter(contentType) {
			// force attachment for allowed content type
			contentDispositionBytes = contentDispositionForceAttachment(contentDispositionBytes, parsedURI)
		} else {
			// deny access to forbidden content type
			// HTTP status code 403 : Forbidden
			p.serveMainPage(ctx, fasthttp.StatusForbidden, errors.New("forbidden content type "+parsedURI.String()))
			return
		}
	}

	// HACK : replace */xhtml by text/html
	if contentType.SubType == "xhtml" {
		contentType.TopLevelType = "text"
		contentType.SubType = "html"
		contentType.Suffix = ""
	}

	// conversion to UTF-8
	var responseBody []byte

	if contentType.TopLevelType == "text" {
		e, ename, _ := charset.DetermineEncoding(resp.Body(), contentTypeString)
		if (e != encoding.Nop) && (!strings.EqualFold("utf-8", ename)) {
			responseBody, err = e.NewDecoder().Bytes(resp.Body())
			if err != nil {
				// HTTP status code 503 : Service Unavailable
				p.serveMainPage(ctx, fasthttp.StatusServiceUnavailable, err)
				return
			}
		} else {
			responseBody = resp.Body()
		}
		// update the charset or specify it
		contentType.Parameters["charset"] = "UTF-8"
	} else {
		responseBody = resp.Body()
	}

	contentType.FilterParameters(allowedContentTypeParameters)

	// set the content type
	ctx.SetContentType(contentType.String())

	// output according to MIME type
	switch {
	case contentType.SubType == "css" && contentType.Suffix == "":
		setSecurityHeaders(ctx, "")
		sanitizeCSS(&RequestConfig{Key: p.Key, BaseURL: parsedURI}, ctx, responseBody)
	case contentType.SubType == "html" && contentType.Suffix == "":
		setSecurityHeaders(ctx, documentCSP)
		rc := &RequestConfig{Key: p.Key, BaseURL: parsedURI}
		sanitizeHTML(rc, ctx, responseBody)
		if !rc.BodyInjected {
			param := htmlBodyExtParam{rc.BaseURL.String(), false}
			if len(rc.Key) > 0 {
				param.HasMortyKey = true
			}
			if err := htmlBodyExtension.Execute(ctx, param); err != nil && cfg.Debug {
				log.Println("failed to inject body extension:", err)
			}
		}
	default:
		setSecurityHeaders(ctx, "")
		if contentDispositionBytes != nil {
			ctx.Response.Header.AddBytesV("Content-Disposition", contentDispositionBytes)
		}
		ctx.Write(responseBody)
	}
}

// force content-disposition to attachment
func contentDispositionForceAttachment(contentDispositionBytes []byte, uri *url.URL) []byte {
	var contentDispositionParams map[string]string

	if contentDispositionBytes != nil {
		var err error
		_, contentDispositionParams, err = mime.ParseMediaType(string(contentDispositionBytes))
		if err != nil {
			contentDispositionParams = make(map[string]string)
		}
	} else {
		contentDispositionParams = make(map[string]string)
	}

	if _, fileNameDefined := contentDispositionParams["filename"]; !fileNameDefined {
		contentDispositionParams["filename"] = sanitizeFilename(filepath.Base(uri.Path))
	}

	return []byte(mime.FormatMediaType("attachment", contentDispositionParams))
}

// sanitizeFilename strips characters that are invalid or dangerous in a
// Content-Disposition filename parameter.
func sanitizeFilename(name string) string {
	name = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f || strings.ContainsRune(`"/\<>:?|`, r) {
			return -1
		}
		return r
	}, name)
	name = strings.TrimSpace(strings.Trim(name, "."))
	if name == "" || len(name) > 128 {
		return "download"
	}
	return name
}

func appRequestHandler(ctx *fasthttp.RequestCtx) bool {
	switch string(ctx.Path()) {
	case "/robots.txt":
		ctx.SetContentType("text/plain")
		ctx.Write([]byte("User-Agent: *\nDisallow: /\n"))
		return true
	case "/favicon.ico":
		ctx.SetContentType("image/png")
		ctx.Write(faviconBytes)
		return true
	case "/healthz":
		setSecurityHeaders(ctx, "")
		ctx.SetContentType("text/plain; charset=utf-8")
		ctx.Write([]byte("ok\n"))
		return true
	}
	return false
}

func popRequestParam(ctx *fasthttp.RequestCtx, paramName []byte) []byte {
	param := ctx.QueryArgs().PeekBytes(paramName)

	if param == nil {
		param = ctx.PostArgs().PeekBytes(paramName)
		ctx.PostArgs().DelBytes(paramName)
	}
	ctx.QueryArgs().DelBytes(paramName)

	return param
}

func sanitizeCSS(rc *RequestConfig, out io.Writer, css []byte) {
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
		} else if cfg.Debug {
			log.Println("cannot proxify css uri:", string(css[urlStart:urlEnd]))
		}
	}
	if startIndex < len(css) {
		out.Write(css[startIndex:])
	}
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
				log.Println("failed to parse HTML")
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
				var attrs [][][]byte
				if hasAttrs {
					for {
						attrName, attrValue, moreAttr := decoder.TagAttr()
						attrs = append(attrs, [][]byte{
							attrName,
							attrValue,
							[]byte(html.EscapeString(string(attrValue))),
						})
						if !moreAttr {
							break
						}
					}
				}
				if bytes.Equal(tag, []byte("link")) {
					sanitizeLinkTag(rc, out, attrs)
					break
				}

				if bytes.Equal(tag, []byte("meta")) {
					sanitizeMetaTag(rc, out, attrs)
					break
				}

				fmt.Fprintf(out, "<%s", tag)

				if hasAttrs {
					sanitizeAttrs(rc, out, attrs)
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

				if bytes.Equal(tag, []byte("form")) {
					formURL := rc.BaseURL
					for _, attr := range attrs {
						if bytes.Equal(attr[0], []byte("action")) {
							if parsed, err := rc.BaseURL.Parse(string(attr[1])); err == nil {
								formURL = parsed
							}
							break
						}
					}
					urlStr := formURL.String()
					var key string
					if rc.Key != nil {
						key = hash(urlStr, rc.Key)
					}
					if err := htmlFormExtension.Execute(out, htmlFormExtParam{urlStr, key}); err != nil && cfg.Debug {
						log.Println("failed to inject form extension:", err)
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
					if err := htmlBodyExtension.Execute(out, param); err != nil && cfg.Debug {
						log.Println("failed to inject body extension:", err)
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
					fmt.Fprintf(out, "</%s>", tag)
				}

			case html.TextToken:
				switch state {
				case stateDefault:
					fmt.Fprintf(out, "%s", decoder.Raw())
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

func sanitizeLinkTag(rc *RequestConfig, out io.Writer, attrs [][][]byte) {
	exclude := false
	for _, attr := range attrs {
		attrName := attr[0]
		attrValue := attr[1]
		if bytes.Equal(attrName, []byte("rel")) && !inArray(attrValue, linkRelSafeValues) {
			exclude = true
			break
		}
		if bytes.Equal(attrName, []byte("as")) && bytes.Equal(attrValue, []byte("script")) {
			exclude = true
			break
		}
	}

	if !exclude {
		out.Write([]byte("<link"))
		for _, attr := range attrs {
			sanitizeAttr(rc, out, attr[0], attr[1], attr[2])
		}
		out.Write([]byte(">"))
	}
}

func sanitizeMetaTag(rc *RequestConfig, out io.Writer, attrs [][][]byte) {
	var httpEquiv []byte
	var content []byte

	for _, attr := range attrs {
		attrName := attr[0]
		attrValue := attr[1]
		if bytes.Equal(attrName, []byte("http-equiv")) {
			httpEquiv = bytes.ToLower(attrValue)
			// exclude some <meta http-equiv="..." ..>
			if !inArray(httpEquiv, linkHTTPEquivSafeValues) {
				return
			}
		}
		if bytes.Equal(attrName, []byte("content")) {
			content = attrValue
		}
		if bytes.Equal(attrName, []byte("charset")) {
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
			fmt.Fprintf(out, ` http-equiv="refresh" content="%surl=%s"`, content[:urlIndex], html.EscapeString(uri))
		}
	} else {
		if len(httpEquiv) > 0 {
			fmt.Fprintf(out, ` http-equiv="%s"`, httpEquiv)
		}
		sanitizeAttrs(rc, out, attrs)
	}
	out.Write([]byte(">"))
}

func sanitizeAttrs(rc *RequestConfig, out io.Writer, attrs [][][]byte) {
	for _, attr := range attrs {
		sanitizeAttr(rc, out, attr[0], attr[1], attr[2])
	}
}

func sanitizeAttr(rc *RequestConfig, out io.Writer, attrName, attrValue, escapedAttrValue []byte) {
	if inArray(attrName, safeAttributes) {
		fmt.Fprintf(out, " %s=\"%s\"", attrName, escapedAttrValue)
		return
	}
	switch string(attrName) {
	case "src", "href", "action":
		if uri, err := rc.ProxifyURI(attrValue); err == nil {
			fmt.Fprintf(out, " %s=\"%s\"", attrName, html.EscapeString(uri))
		} else if cfg.Debug {
			log.Println("cannot proxify uri:", string(attrValue))
		}
	case "srcset":
		fmt.Fprintf(out, " %s=\"%s\"", attrName, html.EscapeString(proxifySrcSet(rc, attrValue)))
	case "style":
		cssAttr := bytes.NewBuffer(nil)
		sanitizeCSS(rc, cssAttr, attrValue)
		fmt.Fprintf(out, " %s=\"%s\"", attrName, html.EscapeString(cssAttr.String()))
	}
}

// proxifySrcSet rewrites every URL in a srcset attribute value.
// A srcset entry is "url descriptor1, descriptor2" separated by commas.
func proxifySrcSet(rc *RequestConfig, value []byte) string {
	var b strings.Builder
	for i, entry := range bytes.Split(value, []byte(",")) {
		entry = bytes.TrimSpace(entry)
		if len(entry) == 0 {
			continue
		}
		if i > 0 {
			b.WriteString(", ")
		}
		parts := bytes.Fields(entry)
		if len(parts) == 0 {
			continue
		}
		if uri, err := rc.ProxifyURI(parts[0]); err == nil {
			b.WriteString(uri)
		} else {
			b.Write(parts[0])
		}
		for _, descriptor := range parts[1:] {
			b.WriteByte(' ')
			b.Write(descriptor)
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

	if rc.Key == nil {
		return fmt.Sprintf("./?mortyurl=%s%s", url.QueryEscape(mortyURI), fragment), nil
	}
	return fmt.Sprintf("./?mortyhash=%s&mortyurl=%s%s", hash(mortyURI, rc.Key), url.QueryEscape(mortyURI), fragment), nil
}

func inArray(b []byte, a [][]byte) bool {
	for _, b2 := range a {
		if bytes.Equal(b, b2) {
			return true
		}
	}
	return false
}

func hash(msg string, key []byte) string {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(msg))
	return hex.EncodeToString(mac.Sum(nil))
}

func verifyRequestURI(uri, hashMsg, key []byte) bool {
	h := make([]byte, hex.DecodedLen(len(hashMsg)))
	if _, err := hex.Decode(h, hashMsg); err != nil {
		if cfg.Debug {
			log.Println("hmac error:", err)
		}
		return false
	}
	mac := hmac.New(sha256.New, key)
	mac.Write(uri)
	return hmac.Equal(h, mac.Sum(nil))
}

func (p *Proxy) serveExitMortyPage(ctx *fasthttp.RequestCtx, uri *url.URL) {
	ctx.SetContentType("text/html")
	ctx.SetStatusCode(fasthttp.StatusForbidden)
	setSecurityHeaders(ctx, pageCSP)
	ctx.Write([]byte(mortyHTMLPageStart))
	ctx.Write([]byte("<h2>You are about to exit MortyProxy</h2>"))
	ctx.Write([]byte("<p>Following</p><p><a href=\""))
	ctx.Write([]byte(html.EscapeString(uri.String())))
	ctx.Write([]byte("\" rel=\"noreferrer\">"))
	ctx.Write([]byte(html.EscapeString(uri.String())))
	ctx.Write([]byte("</a></p><p>the content of this URL will be <b>NOT</b> sanitized.</p>"))
	ctx.Write([]byte(mortyHTMLPageEnd))
}

func (p *Proxy) serveMainPage(ctx *fasthttp.RequestCtx, statusCode int, err error) {
	ctx.SetContentType("text/html; charset=UTF-8")
	ctx.SetStatusCode(statusCode)
	setSecurityHeaders(ctx, pageCSP)
	ctx.Write([]byte(mortyHTMLPageStart))
	if err != nil {
		if cfg.Debug {
			log.Println("error:", err)
		}
		ctx.Write([]byte("<h2>Error: "))
		ctx.Write([]byte(html.EscapeString(err.Error())))
		ctx.Write([]byte("</h2>"))
	}
	if p.Key == nil {
		ctx.Write([]byte(`
		<form method="get">
		Visit url: <input placeholder="https://url.." name="mortyurl" autofocus />
		<input type="submit" value="go" />
		</form>`))
	} else {
		ctx.Write([]byte(`<h3>Warning! This instance does not support direct URL opening.</h3>`))
	}
	ctx.Write([]byte(mortyHTMLPageEnd))
}

func run() error {
	listenAddress := flag.String("listen", cfg.ListenAddress, "Listen address")
	key := flag.String("key", cfg.Key, "HMAC url validation key (base64 encoded) - leave blank to disable validation")
	ipv6 := flag.Bool("ipv6", cfg.IPv6, "Allow IPv6 HTTP requests")
	debug := flag.Bool("debug", cfg.Debug, "Debug mode")
	requestTimeout := flag.Uint("timeout", cfg.RequestTimeout, "Request timeout")
	followRedirect := flag.Bool("followredirect", cfg.FollowRedirect, "Follow HTTP GET redirect")
	proxyenv := flag.Bool("proxyenv", false, "Use a HTTP proxy as set in the environment (HTTP_PROXY, HTTPS_PROXY and NO_PROXY). Overrides -proxy, -socks5, -ipv6.")
	proxy := flag.String("proxy", "", "Use the specified HTTP proxy (ie: '[user:pass@]hostname:port'). Overrides -socks5, -ipv6.")
	socks5 := flag.String("socks5", "", "Use a SOCKS5 proxy (ie: 'hostname:port'). Overrides -ipv6.")
	showVersion := flag.Bool("version", false, "Show version")
	flag.Parse()

	cfg.ListenAddress = *listenAddress
	cfg.Key = *key
	cfg.IPv6 = *ipv6
	cfg.Debug = *debug
	cfg.RequestTimeout = *requestTimeout
	cfg.FollowRedirect = *followRedirect

	if *showVersion {
		fmt.Println(version)
		return nil
	}

	if *proxyenv && os.Getenv("HTTP_PROXY") == "" && os.Getenv("HTTPS_PROXY") == "" {
		return errors.New("-proxyenv is used but no environment variables named 'HTTP_PROXY' and/or 'HTTPS_PROXY' could be found")
	}

	switch {
	case *proxyenv:
		client.Dial = fasthttpproxy.FasthttpProxyHTTPDialer()
		log.Println("Using environment defined proxy(ies).")
	case *proxy != "":
		client.Dial = fasthttpproxy.FasthttpHTTPDialer(*proxy)
		log.Println("Using custom HTTP proxy.")
	case *socks5 != "":
		client.Dial = fasthttpproxy.FasthttpSocksDialer(*socks5)
		log.Println("Using Socks5 proxy.")
	case cfg.IPv6:
		client.Dial = fasthttp.DialDualStack
		log.Println("Using dual stack (IPv4/IPv6) direct connections.")
	default:
		client.Dial = fasthttp.Dial
		log.Println("Using IPv4 only direct connections.")
	}

	const maxRequestTimeout = 3600 // 1 hour
	timeout := cfg.RequestTimeout
	if timeout == 0 || timeout > maxRequestTimeout {
		log.Printf("invalid -timeout value %d, using %d seconds", timeout, maxRequestTimeout)
		timeout = maxRequestTimeout
	}

	p := &Proxy{
		// #nosec G115 -- timeout is bounded to [1, 3600] above
		RequestTimeout: time.Duration(timeout) * time.Second,
		FollowRedirect: cfg.FollowRedirect,
	}

	if cfg.Key != "" {
		var err error
		p.Key, err = base64.StdEncoding.DecodeString(cfg.Key)
		if err != nil {
			return fmt.Errorf("error parsing -key: %w", err)
		}
	}

	server := &fasthttp.Server{
		Name:               "morty",
		Handler:            p.RequestHandler,
		ReadTimeout:        10 * time.Second,
		WriteTimeout:       p.RequestTimeout + 30*time.Second,
		IdleTimeout:        60 * time.Second,
		MaxRequestBodySize: 4 * 1024 * 1024,
	}

	listener, err := net.Listen("tcp", cfg.ListenAddress)
	if err != nil {
		return fmt.Errorf("cannot listen on %s: %w", cfg.ListenAddress, err)
	}

	log.Println("listening on", cfg.ListenAddress)

	serveErr := make(chan error, 1)
	go func() {
		serveErr <- server.Serve(listener)
	}()

	stopCtx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	select {
	case err := <-serveErr:
		return err
	case <-stopCtx.Done():
		log.Println("shutting down")
		return server.Shutdown()
	}
}

func main() {
	if err := run(); err != nil {
		log.Fatal("Error:", err)
	}
}
