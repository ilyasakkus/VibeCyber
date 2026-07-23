package scan

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestCollectFilesDoesNotFollowSymlinks(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink setup requires privileges on some Windows systems")
	}
	root := t.TempDir()
	outside := filepath.Join(t.TempDir(), "secret.txt")
	if err := os.WriteFile(outside, []byte("outside"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "inside.txt"), []byte("inside"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "link.txt")); err != nil {
		t.Fatal(err)
	}
	tree, err := collectFiles(root, DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	defer tree.Close()
	files, stats := tree.Files, tree.Stats
	if len(files) != 1 || files[0].Relative != "inside.txt" {
		t.Fatalf("unexpected files: %#v", files)
	}
	if stats.Symlinks != 1 {
		t.Fatalf("symlinks = %d, want 1", stats.Symlinks)
	}
}

func TestPathWithin(t *testing.T) {
	root := filepath.Join(string(filepath.Separator), "tmp", "root")
	if !pathWithin(root, filepath.Join(root, "a", "b")) {
		t.Fatal("child should be within root")
	}
	if pathWithin(root, filepath.Join(root, "..", "escape")) {
		t.Fatal("parent traversal should be rejected")
	}
}

func TestMetadataRejectsSymlinkBeforeHashing(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink setup requires privileges on some Windows systems")
	}
	outside := filepath.Join(t.TempDir(), "outside.bin")
	if err := os.WriteFile(outside, []byte("sensitive"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(t.TempDir(), "artifact.bin")
	if err := os.Symlink(outside, link); err != nil {
		t.Fatal(err)
	}
	if _, err := collectFiles(link, DefaultLimits()); err == nil {
		t.Fatal("bounded collection followed a target symlink")
	}
}

func TestRootBoundedOpenRejectsIntermediateSymlinkRace(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink setup requires privileges on some Windows systems")
	}
	root := t.TempDir()
	insideDir := filepath.Join(root, "nested")
	if err := os.Mkdir(insideDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(insideDir, "artifact.txt"), []byte("inside"), 0o600); err != nil {
		t.Fatal(err)
	}
	outsideDir := t.TempDir()
	secret := "OUTSIDE_SECRET_MUST_NOT_BE_READ"
	if err := os.WriteFile(filepath.Join(outsideDir, "artifact.txt"), []byte(secret), 0o600); err != nil {
		t.Fatal(err)
	}
	tree := collectTargetForTest(t, root)
	defer tree.Close()
	var record fileRecord
	for _, candidate := range tree.Files {
		if candidate.Relative == "nested/artifact.txt" {
			record = candidate
		}
	}
	if record.root == nil {
		t.Fatal("bounded record was not collected")
	}
	if err := os.Rename(insideDir, filepath.Join(root, "nested-original")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outsideDir, insideDir); err != nil {
		t.Fatal(err)
	}
	data, _, err := readLimitedFile(record, 1<<20)
	if err == nil || strings.Contains(string(data), secret) {
		t.Fatalf("intermediate symlink race escaped root: err=%v data=%q", err, data)
	}
}

func collectTargetForTest(t *testing.T, target string) *targetTree {
	t.Helper()
	tree, err := collectFiles(target, DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	return tree
}
