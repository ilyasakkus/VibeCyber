package scan

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

func TestStableMetadataHashMatchesExactlyHashedBytes(t *testing.T) {
	content := []byte("stable artifact bytes")
	filename := filepath.Join(t.TempDir(), "artifact.bin")
	if err := os.WriteFile(filename, content, 0o600); err != nil {
		t.Fatal(err)
	}
	tree := collectTargetForTest(t, filename)
	defer tree.Close()
	metadata, partial, err := inspectTargetMetadata(tree, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	want := sha256.Sum256(content)
	if partial || metadata["sha256"] != hex.EncodeToString(want[:]) || metadata["bytes_hashed"] != "21" || metadata["sha256_status"] != "complete" {
		t.Fatalf("inconsistent hash metadata: %#v partial=%v", metadata, partial)
	}
}

func TestHashStableFileRejectsGrowthInsteadOfPublishingPrefixHash(t *testing.T) {
	filename := filepath.Join(t.TempDir(), "growing.bin")
	if err := os.WriteFile(filename, []byte("prefix"), 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(filename, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	initial, err := f.Stat()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteAt([]byte("-growth"), initial.Size()); err != nil {
		t.Fatal(err)
	}
	digest, bytesHashed, stable, err := hashStableFile(f, initial, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	if stable || digest != "" || bytesHashed != initial.Size() {
		t.Fatalf("growth published a prefix hash: digest=%q bytes=%d stable=%v", digest, bytesHashed, stable)
	}
}
