package model

import (
	"strings"
	"testing"
)

func TestNormalizeFindingsDeduplicatesAndSorts(t *testing.T) {
	low := Finding{RuleID: "low", Module: "test", Severity: SeverityLow, Evidence: Evidence{Location: "a", Line: 1}}
	high := Finding{RuleID: "high", Module: "test", Severity: SeverityHigh, Evidence: Evidence{Location: "b", Line: 2}}
	got := NormalizeFindings([]Finding{low, high, low})
	if len(got) != 2 {
		t.Fatalf("got %d findings, want 2", len(got))
	}
	if got[0].RuleID != "high" {
		t.Fatalf("first rule = %q, want high", got[0].RuleID)
	}
	if got[0].Fingerprint == "" || got[1].Fingerprint == "" {
		t.Fatal("fingerprints were not populated")
	}
}

func TestFingerprintDoesNotIncludeSnippet(t *testing.T) {
	a := Finding{RuleID: "secret", Module: "source", Evidence: Evidence{Location: "x", Line: 4, Snippet: "[REDACTED:a]"}}
	b := a
	b.Evidence.Snippet = "[REDACTED:b]"
	if Fingerprint(a) != Fingerprint(b) {
		t.Fatal("secret snippet changed fingerprint")
	}
}

func TestFingerprintKeepsSeparateDependenciesAtSameLocation(t *testing.T) {
	a := Finding{RuleID: "dependency", Module: "source", Evidence: Evidence{Location: "package.json", Details: map[string]string{"dependency": "one"}}}
	b := a
	b.Evidence.Details = map[string]string{"dependency": "two"}
	if Fingerprint(a) == Fingerprint(b) {
		t.Fatal("distinct dependency findings were deduplicated")
	}
}

func TestNormalizeBoundsUntrustedEvidence(t *testing.T) {
	long := strings.Repeat("x", 3_000)
	got := NormalizeFindings([]Finding{{RuleID: "test", Module: "test", Description: long, Evidence: Evidence{Location: long, Snippet: long, Details: map[string]string{"value": long}}}})
	if len([]rune(got[0].Description)) > 2_003 || len([]rune(got[0].Evidence.Location)) > 1_027 || len([]rune(got[0].Evidence.Snippet)) > 515 {
		t.Fatal("normalized finding exceeded evidence bounds")
	}
}

func TestNormalizeNeverTrustsExternalFingerprint(t *testing.T) {
	a := Finding{RuleID: "one", Module: "test", Fingerprint: "attacker-controlled", Evidence: Evidence{Location: "a"}}
	b := Finding{RuleID: "two", Module: "test", Fingerprint: "attacker-controlled", Evidence: Evidence{Location: "b"}}
	got := NormalizeFindings([]Finding{a, b})
	if len(got) != 2 {
		t.Fatalf("external fingerprint incorrectly deduplicated findings: %d", len(got))
	}
	for _, finding := range got {
		if finding.Fingerprint == "attacker-controlled" || finding.Fingerprint != Fingerprint(finding) {
			t.Fatalf("non-canonical fingerprint: %q", finding.Fingerprint)
		}
	}
}

func TestAddFindingDeduplicatesBeforeUniqueCap(t *testing.T) {
	var report Report
	first := Finding{RuleID: "rule", Module: "test", Fingerprint: "untrusted", Evidence: Evidence{Location: "a"}}
	if got := report.AddFinding(first, 2); got != FindingAdded {
		t.Fatalf("first add = %v", got)
	}
	first.Fingerprint = "different-untrusted-value"
	if got := report.AddFinding(first, 2); got != FindingDuplicate {
		t.Fatalf("duplicate add = %v", got)
	}
	if got := report.AddFinding(Finding{RuleID: "rule", Module: "test", Evidence: Evidence{Location: "b"}}, 2); got != FindingAdded {
		t.Fatalf("second unique add = %v", got)
	}
	if got := report.AddFinding(Finding{RuleID: "rule", Module: "test", Evidence: Evidence{Location: "c"}}, 2); got != FindingCapped {
		t.Fatalf("third unique add = %v", got)
	}
	if len(report.Findings) != 2 {
		t.Fatalf("finding count = %d", len(report.Findings))
	}
}
