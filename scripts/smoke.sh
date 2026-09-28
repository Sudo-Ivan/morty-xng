#!/usr/bin/env bash
# smoke.sh - quick end-to-end checks against a running morty binary.
# Usage: ./scripts/smoke.sh [path-to-binary] [port]
set -u

BIN="${1:-./morty}"
PORT="${2:-3010}"
BASE="http://127.0.0.1:${PORT}"
KEY="dGVzdGtleQ==" # base64("testkey")
FAIL=0

check() { # name expected actual
    if [ "$2" = "$3" ]; then
        echo "PASS  $1"
    else
        echo "FAIL  $1 (expected $2, got $3)"
        FAIL=1
    fi
}

enc() { printf '%s' "$1" | python3 -c 'import urllib.parse,sys; print(urllib.parse.quote(sys.stdin.read()))'; }

cleanup() { [ -n "${PID:-}" ] && kill "$PID" 2>/dev/null; }
trap cleanup EXIT

"$BIN" -listen "127.0.0.1:${PORT}" -debug=false &
PID=$!
sleep 0.5

check "healthz" "ok" "$(curl -sf "${BASE}/healthz" | tr -d '\n')"
check "main page" "200" "$(curl -s -o /dev/null -w '%{http_code}' "${BASE}/")"
check "robots disallow" "0" "$(curl -s "${BASE}/robots.txt" | grep -c 'Disallow: /' >/dev/null; echo $?)"
check "public proxify" "200" "$(curl -s -o /dev/null -w '%{http_code}' "${BASE}/?mortyurl=$(enc https://example.com/)")"
check "ssrf localhost blocked" "500" "$(curl -s -o /dev/null -w '%{http_code}' "${BASE}/?mortyurl=$(enc http://127.0.0.1:1/)")"
check "ssrf metadata blocked" "500" "$(curl -s -o /dev/null -w '%{http_code}' "${BASE}/?mortyurl=$(enc http://169.254.169.254/)")"
check "onion exit page" "403" "$(curl -s -o /dev/null -w '%{http_code}' "${BASE}/?mortyurl=$(enc http://check.torproject.org.onion/)")"
check "security header nosniff" "nosniff" "$(curl -sI "${BASE}/healthz" | tr -d '\r' | awk 'tolower($1)=="x-content-type-options:"{print $2}')"

kill "$PID" 2>/dev/null; wait "$PID" 2>/dev/null

# keyed mode: unsigned requests must be rejected
"$BIN" -listen "127.0.0.1:${PORT}" -key "$KEY" -debug=false &
PID=$!
sleep 0.5
check "keyed rejects unsigned" "403" "$(curl -s -o /dev/null -w '%{http_code}' "${BASE}/?mortyurl=$(enc https://example.com/)")"

if [ "$FAIL" -eq 0 ]; then
    echo "smoke: all checks passed"
else
    echo "smoke: failures found"
fi
exit "$FAIL"
