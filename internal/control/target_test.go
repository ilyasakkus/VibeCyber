package control

import (
	"testing"

	"github.com/webcyber/webcyber/internal/model"
	"github.com/webcyber/webcyber/internal/scan"
)

func TestPublicTargetRedactsWebCredentialsQueryAndFragment(t *testing.T) {
	raw := "HTTPS://alice:super-secret@example.test:8443/a/path?api_key=private-token#session-token"
	got := publicTarget(scan.Config{Type: model.ScanTypeWeb, Target: raw})
	want := "https://example.test:8443/a/path"
	if got != want {
		t.Fatalf("publicTarget() = %q, want %q", got, want)
	}
}

func TestPublicTargetRejectsMalformedOrNonAbsoluteWebTargets(t *testing.T) {
	for _, raw := range []string{
		"",
		"not a URL",
		"/relative/path?token=secret",
		"ftp://user:secret@example.test/file?token=secret",
		"https://",
		"https:example.test/path?token=secret",
		"https://example.test/\n?token=secret",
	} {
		if got := publicTarget(scan.Config{Type: model.ScanTypeWeb, Target: raw}); got != invalidWebTarget {
			t.Errorf("publicTarget(%q) = %q, want %q", raw, got, invalidWebTarget)
		}
	}
}

func TestPublicTargetLeavesLocalTargetsUnchanged(t *testing.T) {
	raw := "/tmp/project with spaces"
	for _, scanType := range []model.ScanType{
		model.ScanTypeSource,
		model.ScanTypeMobile,
		model.ScanTypeDesktop,
	} {
		if got := publicTarget(scan.Config{Type: scanType, Target: raw}); got != raw {
			t.Errorf("publicTarget(%s) = %q, want %q", scanType, got, raw)
		}
	}
}
