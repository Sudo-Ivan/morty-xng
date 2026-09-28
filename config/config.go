package config

import (
	"os"
	"strconv"
)

// Config holds the runtime configuration of the proxy.
// Values are populated from environment variables and can be
// overridden by command line flags.
type Config struct {
	Debug          bool
	ListenAddress  string
	Key            string
	KeyTTL         uint
	IPv6           bool
	RequestTimeout uint
	FollowRedirect bool
	AllowPrivate   bool
	RateLimit      uint
	UserAgent      string
	AllowHosts     string
	DenyHosts      string
	Metrics        bool
	CacheSize      uint
	CacheTTL       uint
}

// DefaultConfig is initialized from the environment at startup.
//
// Supported environment variables:
//
//	MORTY_ADDRESS         listen address (default "127.0.0.1:3000")
//	MORTY_KEY             base64 encoded HMAC url validation key
//	MORTY_KEYTTL          signed url lifetime in seconds (default 0, no expiry)
//	MORTY_DEBUG or DEBUG  enable request logging (default true)
//	MORTY_IPV6            allow IPv6 upstream requests (default true)
//	MORTY_TIMEOUT         upstream request timeout in seconds (default 5)
//	MORTY_FOLLOWREDIRECT  follow HTTP GET redirects (default false)
//	MORTY_ALLOWPRIVATE    allow requests to private/reserved IPs (default false)
//	MORTY_RATELIMIT       requests per minute per client IP when no key is set (default 60)
//	MORTY_UA              upstream User-Agent header
//	MORTY_ALLOW           comma separated host suffix allowlist
//	MORTY_DENY            comma separated host suffix denylist
//	MORTY_METRICS         enable the /metrics endpoint (default false)
//	MORTY_CACHE           response cache size in MB for static content (default 0, disabled)
//	MORTY_CACHETTL        response cache entry TTL in seconds (default 300)
var DefaultConfig = loadDefaultConfig()

const defaultUserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0"

func loadDefaultConfig() *Config {
	return &Config{
		Debug:          envBool("DEBUG", envBool("MORTY_DEBUG", true)),
		ListenAddress:  envOr("MORTY_ADDRESS", "127.0.0.1:3000"),
		Key:            envOr("MORTY_KEY", ""),
		KeyTTL:         envUint("MORTY_KEYTTL", 0),
		IPv6:           envBool("MORTY_IPV6", true),
		RequestTimeout: envUint("MORTY_TIMEOUT", 5),
		FollowRedirect: envBool("MORTY_FOLLOWREDIRECT", false),
		AllowPrivate:   envBool("MORTY_ALLOWPRIVATE", false),
		RateLimit:      envUint("MORTY_RATELIMIT", 60),
		UserAgent:      envOr("MORTY_UA", defaultUserAgent),
		AllowHosts:     envOr("MORTY_ALLOW", ""),
		DenyHosts:      envOr("MORTY_DENY", ""),
		Metrics:        envBool("MORTY_METRICS", false),
		CacheSize:      envUint("MORTY_CACHE", 0),
		CacheTTL:       envUint("MORTY_CACHETTL", 300),
	}
}

func envOr(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}

func envBool(key string, fallback bool) bool {
	if value := os.Getenv(key); value != "" {
		if parsed, err := strconv.ParseBool(value); err == nil {
			return parsed
		}
	}
	return fallback
}

func envUint(key string, fallback uint) uint {
	if value := os.Getenv(key); value != "" {
		if parsed, err := strconv.ParseUint(value, 10, 32); err == nil {
			return uint(parsed)
		}
	}
	return fallback
}
