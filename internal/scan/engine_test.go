package scan

import (
	"fmt"
	"testing"

	"github.com/webcyber/webcyber/internal/model"
)

func TestFindingCapCountsOnlyCanonicalUniqueFindingsAndMarksPartial(t *testing.T) {
	var report model.Report
	duplicate := model.Finding{RuleID: "rule", Module: "test", Evidence: model.Evidence{Location: "same", Line: 1}}
	for index := 0; index < maxReportFindings+100; index++ {
		appendFinding(&report, duplicate)
	}
	if len(report.Findings) != 1 {
		t.Fatalf("duplicates consumed capacity: %d", len(report.Findings))
	}
	for index := 1; index < maxReportFindings; index++ {
		appendFinding(&report, model.Finding{RuleID: "rule", Module: "test", Evidence: model.Evidence{Location: fmt.Sprintf("file-%d", index)}})
	}
	appendFinding(&report, model.Finding{RuleID: "rule", Module: "test", Evidence: model.Evidence{Location: "over-cap"}})
	if len(report.Findings) != maxReportFindings {
		t.Fatalf("unique finding count = %d", len(report.Findings))
	}
	partial := 0
	for _, module := range report.Modules {
		if module.Name == "finding-output" && module.Status == model.ModulePartial {
			partial++
		}
	}
	if partial != 1 || len(report.Limitations) != 1 {
		t.Fatalf("cap status not represented once: modules=%#v limitations=%#v", report.Modules, report.Limitations)
	}
}
