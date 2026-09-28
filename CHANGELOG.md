# v0.4.0 - 2026.09.28

Hardening and feature release.

- fix: upstream responses are requested with Accept-Encoding identity and
  compressed bodies are decompressed, previously they corrupted the output
- fix: private and reserved upstream IPs are refused at dial time (SSRF
  protection), override with -allowprivate / MORTY_ALLOWPRIVATE
- fix: CSS @import string form and image-set()/ -webkit-image-set() quoted
  entries are proxified instead of leaking direct fetches
- fix: formaction, poster, cite, background, longdesc and usemap attributes
  are proxified; iframe srcdoc is sanitized recursively
- new: signed link expiry via -keyttl / MORTY_KEYTTL and the mortyexp
  parameter, expiry stripping and timestamp tampering are rejected
- new: per-client-IP rate limiting for keyless mode, -ratelimit /
  MORTY_RATELIMIT (default 60/min)
- new: host allowlist and denylist, -allow / -deny, applied to every
  redirect hop
- new: /metrics endpoint in Prometheus format via -metrics / MORTY_METRICS
- new: opt-in in-memory LRU response cache for static content, -cache /
  -cachettl
- new: configurable upstream User-Agent via -ua / MORTY_UA
- new: upstream keep-alive and 60s DNS caching (connection close per
  request removed)
- new: structured logging via log/slog
- new: fuzz targets for the sanitizer, proxifier and content-type parser
  with a fuzz.yml CI job, plus CodeQL analysis
- ci: container builds publish SBOM and provenance attestations, release
  binaries are attested via actions/attest-build-provenance

# v0.3.0 - 2026.09.28

Modernization release.

- Go 1.27.1, fasthttp v1.74.0, x/net v0.59.0, x/text v0.42.0
- fix: Content-Disposition was read from the client request instead of the upstream response
- fix: relative redirect targets were not resolved when following redirects
- fix: POST/PUT requests lost their Content-Type header
- fix: Content-Disposition filename parameter is now named correctly and sanitized
- fix: unsafe void elements like <embed> no longer swallow the rest of the document
- fix: nested unsafe elements leaked tokenizer buffer contents
- fix: proxified URIs in HTML attributes are now HTML-escaped
- fix: main page form markup was invalid
- new: security headers on all responses plus CSP on proxified HTML and morty pages
- new: /healthz endpoint for container health checks
- new: graceful shutdown on SIGTERM/SIGINT
- new: srcset attribute rewriting, more allowed content types (avif, svg fonts, media)
- new: MORTY_DEBUG, MORTY_IPV6, MORTY_TIMEOUT, MORTY_FOLLOWREDIRECT env vars
- new: GitHub Actions CI/CD replacing Travis: tests, multi-OS builds, lint, govulncheck, dependency review, container build and ghcr.io push, tagged releases, OpenSSF Scorecard and zizmor workflow audit
- new: multi-stage Dockerfile, non-root user, static binary, health check

# v0.2.0 - 2018.05.28

Man page added

# v0.1.0 - 2018.01.30

Initial release
