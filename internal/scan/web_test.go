package scan

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/webcyber/webcyber/internal/model"
)

func TestSafeHTTPClientRevalidatesRedirects(t *testing.T) {
	limits := DefaultLimits()
	guard := newSSRFGuard(limits.DialTimeout)
	client, transport := newSafeHTTPClient(guard, limits)
	defer transport.CloseIdleConnections()

	previous := &http.Request{URL: mustURL(t, "http://93.184.216.34/start")}
	toLoopback := &http.Request{URL: mustURL(t, "http://127.0.0.1/admin")}
	if err := client.CheckRedirect(toLoopback, []*http.Request{previous}); err == nil || !strings.Contains(err.Error(), "unsafe redirect") {
		t.Fatalf("loopback redirect error = %v", err)
	}

	securePrevious := &http.Request{URL: mustURL(t, "https://93.184.216.34/start")}
	downgrade := &http.Request{URL: mustURL(t, "http://93.184.216.34/next")}
	if err := client.CheckRedirect(downgrade, []*http.Request{securePrevious}); err == nil || !strings.Contains(err.Error(), "HTTPS-to-HTTP") {
		t.Fatalf("downgrade redirect error = %v", err)
	}

	via := make([]*http.Request, limits.MaxRedirects+1)
	for index := range via {
		via[index] = previous
	}
	if err := client.CheckRedirect(previous, via); err == nil || !strings.Contains(err.Error(), "redirect limit") {
		t.Fatalf("redirect limit error = %v", err)
	}
}

func TestSecurityHeadersAreContentAwareAndDoNotLeakCookieValues(t *testing.T) {
	response := &http.Response{
		Request: &http.Request{URL: mustURL(t, "https://example.com/api")},
		Header: http.Header{
			"Content-Type":              []string{"application/json"},
			"X-Content-Type-Options":    []string{"nosniff"},
			"Strict-Transport-Security": []string{"max-age=31536000"},
			"Set-Cookie":                []string{"session=DO_NOT_LEAK_THIS;HttpOnly;Secure;SameSite=Lax"},
		},
	}
	report := model.Report{}
	inspectSecurityHeaders(response, &report)
	if len(report.Findings) != 0 {
		t.Fatalf("unexpected JSON API findings: %#v", report.Findings)
	}
	encoded, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "DO_NOT_LEAK_THIS") {
		t.Fatal("cookie value leaked into report")
	}
}

func TestSecurityHeaderQualityChecks(t *testing.T) {
	response := &http.Response{
		Request: &http.Request{URL: mustURL(t, "https://example.com/")},
		Header: http.Header{
			"Content-Type":              []string{"text/html"},
			"Content-Security-Policy":   []string{"default-src 'self'; script-src 'unsafe-eval'"},
			"X-Content-Type-Options":    []string{"invalid"},
			"Strict-Transport-Security": []string{"max-age=0"},
		},
	}
	report := model.Report{}
	inspectSecurityHeaders(response, &report)
	rules := make(map[string]bool)
	for _, finding := range report.Findings {
		rules[finding.RuleID] = true
	}
	for _, rule := range []string{"web.header.nosniff.invalid", "web.header.csp.unsafe-eval", "web.header.hsts.weak-max-age"} {
		if !rules[rule] {
			t.Errorf("missing %s", rule)
		}
	}
}

func TestSafeURLDropsCredentialsQueryAndFragment(t *testing.T) {
	input := mustURL(t, "https://user:secret@example.com/path?token=DO_NOT_LEAK#fragment")
	got := safeURL(input)
	if got != "https://example.com/path" {
		t.Fatalf("safe URL = %q", got)
	}
}

func mustURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	parsed, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return parsed
}
