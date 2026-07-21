package model

import "testing"

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
