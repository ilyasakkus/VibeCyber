package scan

import (
	"os"
	"path/filepath"
	"runtime"
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
	_, files, stats, err := collectFiles(root, DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
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
