package report

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/webcyber/webcyber/internal/model"
)

func TestSARIFContainsRulesResultsAndFingerprint(t *testing.T) {
	finding := model.Finding{RuleID: "test.rule", Module: "test", Title: "Test rule", Severity: model.SeverityHigh, Description: "Description", Remediation: "Fix it", Evidence: model.Evidence{Location: "src/main.go", Line: 7}}
	finding.Fingerprint = model.Fingerprint(finding)
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
}
