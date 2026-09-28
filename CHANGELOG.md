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
