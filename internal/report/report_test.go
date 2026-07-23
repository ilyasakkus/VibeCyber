package report

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/webcyber/webcyber/internal/model"
)

func TestSARIFContainsRulesResultsAndFingerprint(t *testing.T) {
	finding := model.Finding{RuleID: "test.rule", Module: "test", Title: "Test rule", Severity: model.SeverityHigh, Description: "Description", Remediation: "Fix it", Fingerprint: "untrusted", Evidence: model.Evidence{Location: "src/a b#c.go", Line: 7}}
	input := model.Report{SchemaVersion: model.SchemaVersion, Tool: model.ToolInfo{Name: "WebCyber", Version: "test"}, Scan: model.ScanInfo{ID: "scan", Status: "completed"}, Findings: []model.Finding{finding}}
	var output bytes.Buffer
	if err := Write(&output, FormatSARIF, input); err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if err := json.Unmarshal(output.Bytes(), &document); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if document["version"] != "2.1.0" {
		t.Fatalf("version = %#v", document["version"])
	}
	runs := document["runs"].([]any)
	results := runs[0].(map[string]any)["results"].([]any)
	partial := results[0].(map[string]any)["partialFingerprints"].(map[string]any)
	if partial["webcyber/v1"] == "" {
		t.Fatal("missing fingerprint")
	}
	if partial["webcyber/v1"] == "untrusted" {
		t.Fatal("SARIF trusted a caller-supplied fingerprint")
	}
	locations := results[0].(map[string]any)["locations"].([]any)
	physical := locations[0].(map[string]any)["physicalLocation"].(map[string]any)
	artifact := physical["artifactLocation"].(map[string]any)
	if artifact["uri"] != "src/a%20b%23c.go" {
		t.Fatalf("artifact URI was not encoded: %#v", artifact["uri"])
	}
}

func TestSARIFArtifactURIEncodesWindowsAndWebLocations(t *testing.T) {
	if got := sarifArtifactURI(`C:\Program Files\WebCyber\a#b.exe`); got != "file:///C:/Program%20Files/WebCyber/a%23b.exe" {
		t.Fatalf("Windows URI = %q", got)
	}
	if got := sarifArtifactURI("https://example.com/a b?q=x y"); got != "https://example.com/a%20b?q=x+y" {
		t.Fatalf("web URI = %q", got)
	}
}
