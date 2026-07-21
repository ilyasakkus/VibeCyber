package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestRunSourceJSON(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "main.go"), []byte("package main\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	code := Run(context.Background(), []string{"scan", "--type", "source", "--target", root, "--profile", "safe", "--format", "json"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	var output struct {
		SchemaVersion string `json:"schema_version"`
		Scan          struct {
			Type string `json:"type"`
		} `json:"scan"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &output); err != nil {
		t.Fatal(err)
	}
	if output.SchemaVersion != "1.0" || output.Scan.Type != "source" {
		t.Fatalf("unexpected output: %#v", output)
	}
}

func TestRunRejectsUnsafeWebURL(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Run(context.Background(), []string{"scan", "--type", "web", "--target", "http://127.0.0.1/", "--format", "json"}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("code=%d, want 1", code)
	}
	if stdout.Len() == 0 || stderr.Len() == 0 {
		t.Fatal("expected machine report and diagnostic")
	}
}

func TestRunUsageError(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := Run(context.Background(), []string{"scan", "--type", "source"}, &stdout, &stderr); code != 2 {
		t.Fatalf("code=%d, want 2", code)
	}
}
