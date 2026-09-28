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
	IPv6           bool
	RequestTimeout uint
	FollowRedirect bool
}

// DefaultConfig is initialized from the environment at startup.
//
// Supported environment variables:
//
//	MORTY_ADDRESS         listen address (default "127.0.0.1:3000")
//	MORTY_KEY             base64 encoded HMAC url validation key
//	MORTY_DEBUG or DEBUG  enable request logging (default true)
//	MORTY_IPV6            allow IPv6 upstream requests (default true)
//	MORTY_TIMEOUT         upstream request timeout in seconds (default 5)
//	MORTY_FOLLOWREDIRECT  follow HTTP GET redirects (default false)
var DefaultConfig = loadDefaultConfig()

func loadDefaultConfig() *Config {
	return &Config{
		Debug:          envBool("DEBUG", envBool("MORTY_DEBUG", true)),
		ListenAddress:  envOr("MORTY_ADDRESS", "127.0.0.1:3000"),
		Key:            envOr("MORTY_KEY", ""),
		IPv6:           envBool("MORTY_IPV6", true),
		RequestTimeout: envUint("MORTY_TIMEOUT", 5),
		FollowRedirect: envBool("MORTY_FOLLOWREDIRECT", false),
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
