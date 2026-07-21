package scan

import (
	"context"
	"net"
	"net/url"
	"strings"
	"testing"
)

type fixedResolver map[string][]net.IPAddr

func (f fixedResolver) LookupIPAddr(_ context.Context, host string) ([]net.IPAddr, error) {
	return f[host], nil
}

func TestSSRFGuardRejectsUnsafeTargets(t *testing.T) {
	tests := []string{
		"file:///etc/passwd",
		"http://user:pass@example.com/",
		"http://127.0.0.1/",
		"http://[::1]/",
		"http://169.254.169.254/latest/meta-data/",
		"http://192.0.2.2/",
		"http://localhost/",
	}
	for _, raw := range tests {
		t.Run(raw, func(t *testing.T) {
			parsed, err := url.Parse(raw)
			if err != nil {
				t.Fatal(err)
			}
			guard := newSSRFGuard(DefaultLimits().DialTimeout)
			if err := guard.validateURL(context.Background(), parsed); err == nil {
				t.Fatalf("unsafe URL %q was accepted", raw)
			}
		})
	}
}

func TestSSRFGuardRejectsMixedDNSAnswersAndPinsPublicAnswer(t *testing.T) {
	guard := newSSRFGuard(DefaultLimits().DialTimeout)
	guard.resolver = fixedResolver{
		"mixed.example":  {{IP: net.ParseIP("93.184.216.34")}, {IP: net.ParseIP("10.0.0.1")}},
		"public.example": {{IP: net.ParseIP("93.184.216.34")}},
	}
	mixed, _ := url.Parse("https://mixed.example")
	if err := guard.validateURL(context.Background(), mixed); err == nil || !strings.Contains(err.Error(), "non-public") {
		t.Fatalf("mixed answer error = %v", err)
	}
	public, _ := url.Parse("https://public.example")
	if err := guard.validateURL(context.Background(), public); err != nil {
		t.Fatalf("public URL rejected: %v", err)
	}
	guard.resolver = fixedResolver{"public.example": {{IP: net.ParseIP("127.0.0.1")}}}
	addresses, err := guard.resolveAndPin(context.Background(), "public.example")
	if err != nil || addresses[0].IP.String() != "93.184.216.34" {
		t.Fatalf("pinned addresses = %v, err = %v", addresses, err)
	}
}
