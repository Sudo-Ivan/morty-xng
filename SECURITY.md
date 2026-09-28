# Security policy

## Reporting a vulnerability

Please report vulnerabilities privately through a GitHub security advisory:

https://github.com/Sudo-Ivan/morty-xng/security/advisories/new

Do not open a public issue for a vulnerability.

## Scope

Morty is a content sanitizer proxy. Reports are especially welcome for:

- Sanitizer bypasses that allow scripts, unsafe elements, or direct
  third-party resource loads to reach the client
- SSRF paths that reach private or reserved addresses despite the default
  protections, including DNS rebinding and redirect-based bypasses
- URL signature (mortyhash/mortyexp) verification bypasses
- Header injection or response splitting through upstream-controlled data

## Hardening defaults

- Private and reserved upstream IPs are refused unless `-allowprivate` /
  `MORTY_ALLOWPRIVATE` is set
- An unkeyed instance is an open relay: keep it behind `-ratelimit` (on by
  default) and do not expose it to untrusted networks
- Prefer running with `-key` so only signed URLs are fetched
