# Morty

[![CI](https://github.com/Sudo-Ivan/morty-xng/actions/workflows/ci.yml/badge.svg)](https://github.com/Sudo-Ivan/morty-xng/actions/workflows/ci.yml)
[![Docker](https://github.com/Sudo-Ivan/morty-xng/actions/workflows/docker.yml/badge.svg)](https://github.com/Sudo-Ivan/morty-xng/actions/workflows/docker.yml)
[![License: AGPL v3](https://img.shields.io/badge/License-AGPL%20v3-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)

Web content sanitizer proxy as a service.

Morty rewrites web pages to exclude malicious HTML tags and attributes. It also replaces external resource references to prevent third party information leaks.

The main goal of morty is to provide a result proxy for [searx](https://asciimoo.github.com/searx/) and compatible SearXNG setups, but it can be used as a standalone sanitizer service too.

Features:

 - HTML sanitization
 - Rewrites HTML/CSS external references to locals
 - JavaScript blocking
 - No Cookies forwarded
 - No Referrers
 - No Caching/Etag
 - Supports GET/POST forms and IFrames
 - Optional HMAC URL verifier key to prevent service abuse
 - Optional expiring signed links (`mortyexp` + `-keyttl`)
 - SSRF protection: private and reserved IPs are blocked by default
 - Host allow/deny lists
 - Per-IP rate limiting for keyless (open) deployments
 - Security headers on every response (CSP, nosniff, no-referrer)
 - `/healthz` endpoint for container health checks
 - Optional `/metrics` endpoint (Prometheus format)
 - Optional in-memory response cache for static content
 - Graceful shutdown on SIGTERM/SIGINT
 - Upstream keep-alive with short-TTL DNS caching


## Installation and setup

Requirement: Go version 1.27.1 or higher.

```
$ go install github.com/asciimoo/morty@latest
$ morty --help
```

### Usage

```
  -allow string
        Comma separated host suffix allowlist
  -allowprivate
        Allow requests to private/reserved IP ranges
  -cache uint
        Response cache size in MB for static content - 0 disables
  -cachettl uint
        Response cache entry TTL in seconds (default 300)
  -debug
        Debug mode (default true)
  -deny string
        Comma separated host suffix denylist
  -followredirect
        Follow HTTP GET redirect
  -ipv6
        Allow IPv6 HTTP requests (default true)
  -key string
        HMAC url validation key (base64 encoded) - leave blank to disable validation
  -keyttl uint
        Signed url lifetime in seconds - 0 disables expiry
  -listen string
        Listen address (default "127.0.0.1:3000")
  -metrics
        Enable the /metrics endpoint
  -proxy string
        Use the specified HTTP proxy (ie: '[user:pass@]hostname:port'). Overrides -socks5, -ipv6.
  -proxyenv
        Use a HTTP proxy as set in the environment (HTTP_PROXY, HTTPS_PROXY and NO_PROXY). Overrides -proxy, -socks5, -ipv6.
  -ratelimit uint
        Requests per minute per client IP when no key is set (default 60) - 0 disables
  -socks5 string
        Use a SOCKS5 proxy (ie: 'hostname:port'). Overrides -ipv6.
  -timeout uint
        Request timeout in seconds, 1 to 3600 (default 5)
  -ua string
        Upstream User-Agent header
  -version
        Show version
```

### Environment variables

Morty can additionally be configured using the following environment variables:

- `MORTY_ADDRESS`: Listen address (default `127.0.0.1:3000`)
- `MORTY_KEY`: HMAC url validation key (base64 encoded) to prevent direct URL opening. Leave blank to disable validation. Use `openssl rand -base64 33` to generate.
- `MORTY_KEYTTL`: Signed url lifetime in seconds (default `0`, no expiry)
- `MORTY_DEBUG` or `DEBUG`: Enable/disable proxy and redirection logs (default `true`). Set to `false` to disable.
- `MORTY_IPV6`: Allow IPv6 upstream requests (default `true`). Set to `false` for IPv4 only.
- `MORTY_TIMEOUT`: Upstream request timeout in seconds (default `5`)
- `MORTY_FOLLOWREDIRECT`: Follow HTTP GET redirects (default `false`)
- `MORTY_ALLOWPRIVATE`: Allow requests to private/reserved IP ranges (default `false`)
- `MORTY_RATELIMIT`: Requests per minute per client IP when no key is set (default `60`, `0` disables)
- `MORTY_UA`: Upstream User-Agent header
- `MORTY_ALLOW`: Comma separated host suffix allowlist
- `MORTY_DENY`: Comma separated host suffix denylist
- `MORTY_METRICS`: Enable the `/metrics` endpoint (default `false`)
- `MORTY_CACHE`: Response cache size in MB for static content (default `0`, disabled)
- `MORTY_CACHETTL`: Cache entry TTL in seconds (default `300`)


### Security notes

- Requests to private and reserved IPs (loopback, link-local including the
  cloud metadata range `169.254.169.254`, RFC1918, CGNAT, multicast and
  documentation ranges) are refused at dial time. DNS is resolved once and
  the resolved address is dialed directly, so DNS rebinding cannot bypass
  the check. Use `-allowprivate`/`MORTY_ALLOWPRIVATE=true` only for trusted
  internal deployments.
- Without `MORTY_KEY` the proxy accepts any `mortyurl`, so it is an open
  relay by design. `-ratelimit` (default 60/min per client IP) applies in
  this mode only.
- With `MORTY_KEY` and `MORTY_KEYTTL` set, generated links expire. The
  expiry timestamp is covered by the HMAC, so stripping `mortyexp` or
  extending the timestamp invalidates the link.


### SearXNG integration

SearXNG historically supported morty through the `result_proxy` settings
section. SearXNG releases since 2025-05-13 removed `result_proxy` entirely
([searxng#3888](https://github.com/searxng/searxng/issues/3888)), so morty
works out of the box only with:

- searx (the original project)
- SearXNG releases older than 2025.5.13
- SearXNG forks that still ship `result_proxy` (for example tiekoetter)

Add the following to `settings.yml` of a compatible instance:

```yaml
result_proxy:
  url: http://127.0.0.1:3000/
  key: !!binary "your_morty_proxy_key"
  proxify_results: true
```

Each result then gets a "proxied" link that opens through morty. morty
verifies `mortyhash` as HMAC-SHA256 of the URL, which is exactly what
SearXNG generates, so no further setup is needed.

Without a key (`-key`/`MORTY_KEY` unset) morty accepts any URL passed in
`mortyurl`, which is fine for standalone use but must not be exposed to
untrusted networks.


### Containers

The image runs as a non-root user, listens on `0.0.0.0:3000` and ships a
health check against `/healthz`.

With podman:

```
$ podman build -t morty .
$ podman run --rm -e DEBUG=false -e MORTY_ADDRESS=0.0.0.0:3000 -p 127.0.0.1:3000:3000 morty
```

SearXNG and morty on the same network:

```
$ podman network create searxng-net
$ podman run -d --name morty --network searxng-net --network-alias morty \
    -e MORTY_KEY="$(openssl rand -base64 33)" morty
$ podman run -d --name searxng --network searxng-net -p 127.0.0.1:8888:8080 \
    -v ./searxng:/etc/searxng:Z docker.io/searxng/searxng:2025.5.12-5d99373
```

where `./searxng/settings.yml` contains the `result_proxy` section shown
above with `url: "http://morty:3000/"` and the same key.

The same commands work with `docker` instead of `podman`.


### Test

```
$ go test ./...
```


### Benchmark

```
$ go test -benchmem -bench . -run '^$'
```


### Lint and workflow audit

```
$ golangci-lint run ./...
$ zizmor .
```

### Fuzzing

```
$ go test -fuzz=FuzzSanitizeHTML -fuzztime=60s .
$ go test -fuzz=FuzzProxifyURI -fuzztime=60s .
```


## Bugs

Bugs or suggestions? Visit the [issue tracker](https://github.com/asciimoo/morty/issues).
