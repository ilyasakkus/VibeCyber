package scan

import (
	"archive/zip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/webcyber/webcyber/internal/model"
)

func TestInspectZIPFindsTraversalAndExpansionRisk(t *testing.T) {
	filename := filepath.Join(t.TempDir(), "unsafe.zip")
	f, err := os.Create(filename)
	if err != nil {
		t.Fatal(err)
	}
	w := zip.NewWriter(f)
	traversal, err := w.Create("../escape.txt")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := traversal.Write([]byte("escape")); err != nil {
		t.Fatal(err)
	}
	bomb, err := w.Create("large.txt")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := bomb.Write([]byte(strings.Repeat("A", 2<<20))); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	limits := DefaultLimits()
	limits.MaxArchiveEntryBytes = 1 << 20
	report := model.Report{}
	stats, err := inspectZIP(filename, "unsafe.zip", limits, &report, nil)
	if err != nil {
		t.Fatal(err)
	}
	if stats.UnsafePaths != 1 || stats.SuspiciousRatios == 0 {
		t.Fatalf("unexpected stats: %#v", stats)
	}
	rules := map[string]bool{}
	for _, finding := range report.Findings {
		rules[finding.RuleID] = true
	}
	if !rules["archive.path-traversal"] || !rules["archive.decompression-bomb-risk"] {
		t.Fatalf("missing archive findings: %#v", rules)
	}
}

func TestSafeArchiveName(t *testing.T) {
	for _, unsafe := range []string{"../x", "/tmp/x", `..\x`, ""} {
		if _, ok := safeArchiveName(unsafe); ok {
			t.Errorf("accepted unsafe name %q", unsafe)
		}
	}
	if got, ok := safeArchiveName("a/../b.txt"); !ok || got != "b.txt" {
		t.Fatalf("safe normalization = %q, %v", got, ok)
	}
}

func TestInspectZIPPreflightsEntryCount(t *testing.T) {
	filename := filepath.Join(t.TempDir(), "many.zip")
	f, err := os.Create(filename)
	if err != nil {
		t.Fatal(err)
	}
	w := zip.NewWriter(f)
	for _, name := range []string{"one.txt", "two.txt"} {
		if _, err := w.Create(name); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	limits := DefaultLimits()
	limits.MaxArchiveEntries = 1
	report := model.Report{}
	stats, err := inspectZIP(filename, "many.zip", limits, &report, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !stats.LimitHit || len(report.Findings) != 1 || report.Findings[0].RuleID != "archive.entry-limit" {
		t.Fatalf("unexpected preflight result: stats=%#v findings=%#v", stats, report.Findings)
	}
}
