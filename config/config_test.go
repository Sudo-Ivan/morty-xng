package config

import "testing"

func TestEnvOr(t *testing.T) {
	t.Setenv("MORTY_TEST_STR", "value")
	if got := envOr("MORTY_TEST_STR", "fallback"); got != "value" {
		t.Errorf("expected value, got %q", got)
	}
	if got := envOr("MORTY_TEST_MISSING", "fallback"); got != "fallback" {
		t.Errorf("expected fallback, got %q", got)
	}
}

func TestEnvBool(t *testing.T) {
	t.Setenv("MORTY_TEST_TRUE", "true")
	t.Setenv("MORTY_TEST_FALSE", "false")
	t.Setenv("MORTY_TEST_GARBAGE", "yesplease")
	if !envBool("MORTY_TEST_TRUE", false) {
		t.Error("true not parsed")
	}
	if envBool("MORTY_TEST_FALSE", true) {
		t.Error("false not parsed")
	}
	if !envBool("MORTY_TEST_GARBAGE", true) {
		t.Error("unparseable value must keep the fallback")
	}
	if envBool("MORTY_TEST_MISSING", false) {
		t.Error("missing value must keep the fallback")
	}
}

func TestEnvUint(t *testing.T) {
	t.Setenv("MORTY_TEST_NUM", "42")
	t.Setenv("MORTY_TEST_NEG", "-5")
	if got := envUint("MORTY_TEST_NUM", 1); got != 42 {
		t.Errorf("expected 42, got %d", got)
	}
	if got := envUint("MORTY_TEST_NEG", 7); got != 7 {
		t.Errorf("negative value must keep the fallback, got %d", got)
	}
	if got := envUint("MORTY_TEST_MISSING", 7); got != 7 {
		t.Errorf("missing value must keep the fallback, got %d", got)
	}
}
