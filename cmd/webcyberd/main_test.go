package main

import (
	"strings"
	"testing"

	"github.com/webcyber/webcyber/internal/control"
)

func environment(values map[string]string) func(string) string {
	return func(name string) string { return values[name] }
}

func TestLoadConfigDefaultsAndLocalOptIn(t *testing.T) {
	config, err := loadConfig(environment(map[string]string{
		"WEBCYBER_CONTROL_TOKEN": "  0123456789abcdef0123456789abcdef  ",
		"WEBCYBER_ALLOW_LOCAL":   "TrUe",
	}))
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	defaults := control.DefaultManagerConfig()
	if config.address != defaultControlAddress {
		t.Fatalf("address = %q", config.address)
	}
	if config.token != "0123456789abcdef0123456789abcdef" {
		t.Fatalf("token was not trimmed")
	}
	if !config.allowLocal {
		t.Fatal("local path opt-in was not enabled")
	}
	if config.manager != defaults {
		t.Fatalf("manager config = %#v, want %#v", config.manager, defaults)
	}
}

func TestLoadConfigOverridesBounds(t *testing.T) {
	config, err := loadConfig(environment(map[string]string{
		"WEBCYBER_CONTROL_ADDR":    "0.0.0.0:8080",
		"WEBCYBER_CONTROL_TOKEN":   "0123456789abcdef0123456789abcdef",
		"WEBCYBER_MAX_CONCURRENCY": "2",
		"WEBCYBER_MAX_JOBS":        "8",
		"WEBCYBER_MAX_RETAINED":    "12",
	}))
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	if config.address != "0.0.0.0:8080" {
		t.Fatalf("address = %q", config.address)
	}
	if config.manager != (control.ManagerConfig{MaxConcurrency: 2, MaxJobs: 8, MaxRetained: 12}) {
		t.Fatalf("manager config = %#v", config.manager)
	}
}

func TestLoadConfigRejectsMissingOrWeakToken(t *testing.T) {
	for _, token := range []string{"", "short", strings.Repeat("a", 31), strings.Repeat("a", 16) + " " + strings.Repeat("b", 16)} {
		if _, err := loadConfig(environment(map[string]string{"WEBCYBER_CONTROL_TOKEN": token})); err == nil {
			t.Fatalf("token %q was accepted", token)
		}
	}
}

func TestLoadConfigRejectsInvalidBounds(t *testing.T) {
	base := map[string]string{"WEBCYBER_CONTROL_TOKEN": "0123456789abcdef0123456789abcdef"}
	tests := []map[string]string{
		{"WEBCYBER_MAX_CONCURRENCY": "0"},
		{"WEBCYBER_MAX_JOBS": "nope"},
		{"WEBCYBER_MAX_RETAINED": "-1"},
		{"WEBCYBER_MAX_CONCURRENCY": "4", "WEBCYBER_MAX_JOBS": "2"},
	}
	for _, overrides := range tests {
		values := make(map[string]string, len(base)+len(overrides))
		for name, value := range base {
			values[name] = value
		}
		for name, value := range overrides {
			values[name] = value
		}
		if _, err := loadConfig(environment(values)); err == nil {
			t.Fatalf("invalid overrides %#v were accepted", overrides)
		}
	}
}
