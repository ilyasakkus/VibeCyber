package scan

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/binary"
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
	tree := collectTargetForTest(t, filename)
	defer tree.Close()
	stats, err := inspectZIP(tree.Files[0], "unsafe.zip", limits, &report, nil)
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
	tree := collectTargetForTest(t, filename)
	defer tree.Close()
	stats, err := inspectZIP(tree.Files[0], "many.zip", limits, &report, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !stats.LimitHit || len(report.Findings) != 1 || report.Findings[0].RuleID != "archive.entry-limit" {
		t.Fatalf("unexpected preflight result: stats=%#v findings=%#v", stats, report.Findings)
	}
}

func TestZIPPreflightCountsActualRecordsBeforeModuloDeclaration(t *testing.T) {
	filename := filepath.Join(t.TempDir(), "modulo.zip")
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
	data, err := os.ReadFile(filename)
	if err != nil {
		t.Fatal(err)
	}
	eocd := bytes.LastIndex(data, []byte{'P', 'K', 0x05, 0x06})
	if eocd < 0 {
		t.Fatal("EOCD not found")
	}
	binary.LittleEndian.PutUint16(data[eocd+8:eocd+10], 0)
	binary.LittleEndian.PutUint16(data[eocd+10:eocd+12], 0)
	if err := os.WriteFile(filename, data, 0o600); err != nil {
		t.Fatal(err)
	}
	limits := DefaultLimits()
	limits.MaxArchiveEntries = 1
	report := model.Report{}
	tree := collectTargetForTest(t, filename)
	defer tree.Close()
	stats, err := inspectZIP(tree.Files[0], "modulo.zip", limits, &report, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !stats.LimitHit || len(report.Findings) != 1 || report.Findings[0].RuleID != "archive.entry-limit" {
		t.Fatalf("actual central records bypassed limit: stats=%#v findings=%#v", stats, report.Findings)
	}
}

func TestMalformedZIPIsPartialParseErrorNotHighCWE409(t *testing.T) {
	filename := filepath.Join(t.TempDir(), "malformed.zip")
	if err := os.WriteFile(filename, []byte("not a zip archive"), 0o600); err != nil {
		t.Fatal(err)
	}
	report := model.Report{}
	tree := collectTargetForTest(t, filename)
	stats, err := inspectZIP(tree.Files[0], "malformed.zip", DefaultLimits(), &report, nil)
	tree.Close()
	if err == nil {
		t.Fatal("malformed ZIP did not return a parse error")
	}
	if stats.LimitHit || len(report.Findings) != 0 {
		t.Fatalf("malformed ZIP was mislabeled as a security limit: stats=%#v findings=%#v", stats, report.Findings)
	}

	result, scanErr := NewDefault().Scan(context.Background(), Config{Type: model.ScanTypeDesktop, Target: filename, Profile: model.ProfileSafe})
	if scanErr != nil {
		t.Fatal(scanErr)
	}
	if result.Scan.Status != "partial" || len(result.Findings) != 0 {
		t.Fatalf("desktop malformed ZIP result = status %q, findings %#v", result.Scan.Status, result.Findings)
	}
}

func TestArchiveSymlinkEscapeAndChainAreHighTraversal(t *testing.T) {
	filename := filepath.Join(t.TempDir(), "links.zip")
	f, err := os.Create(filename)
	if err != nil {
		t.Fatal(err)
	}
	w := zip.NewWriter(f)
	for name, target := range map[string]string{"direct": "../../escape", "chain-a": "chain-b", "chain-b": "../outside"} {
		header := &zip.FileHeader{Name: name, Method: zip.Store}
		header.SetMode(os.ModeSymlink | 0o777)
		entry, err := w.CreateHeader(header)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := entry.Write([]byte(target)); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	tree := collectTargetForTest(t, filename)
	defer tree.Close()
	report := model.Report{}
	_, err = inspectZIP(tree.Files[0], "links.zip", DefaultLimits(), &report, nil)
	if err != nil {
		t.Fatal(err)
	}
	highTraversal := 0
	for _, finding := range report.Findings {
		if finding.RuleID == "archive.symlink-traversal" && finding.Severity == model.SeverityHigh && finding.CWE == "CWE-22" {
			highTraversal++
		}
	}
	if highTraversal < 2 {
		t.Fatalf("expected direct and chained symlink traversal findings, got %d: %#v", highTraversal, report.Findings)
	}
}
