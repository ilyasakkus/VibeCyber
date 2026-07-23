// Package scan implements WebCyber's built-in, non-executing scanners.
package scan

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/webcyber/webcyber/internal/model"
)

const Version = "0.1.0"

// The report cap is a safety invariant for CLI/UI consumers. Combined with
// bounded evidence strings, it keeps output comfortably below desktop limits.
const maxReportFindings = 2_000

type Config struct {
	Type    model.ScanType
	Target  string
	Profile model.Profile
}

type Limits struct {
	ScanTimeout          time.Duration
	HTTPTimeout          time.Duration
	DialTimeout          time.Duration
	MaxHTTPBodyBytes     int64
	MaxRedirects         int
	MaxFiles             int
	MaxDepth             int
	MaxFileBytes         int64
	MaxTotalBytes        int64
	MaxArchiveEntries    int
	MaxArchiveEntryBytes int64
	MaxArchiveTotalBytes int64
	MaxCompressionRatio  float64
}

func DefaultLimits() Limits {
	return Limits{
		ScanTimeout:          2 * time.Minute,
		HTTPTimeout:          15 * time.Second,
		DialTimeout:          5 * time.Second,
		MaxHTTPBodyBytes:     1 << 20,
		MaxRedirects:         5,
		MaxFiles:             10_000,
		MaxDepth:             40,
		MaxFileBytes:         1 << 20,
		MaxTotalBytes:        32 << 20,
		MaxArchiveEntries:    5_000,
		MaxArchiveEntryBytes: 16 << 20,
		MaxArchiveTotalBytes: 128 << 20,
		MaxCompressionRatio:  100,
	}
}

type Engine struct {
	limits Limits
}

func New(limits Limits) *Engine { return &Engine{limits: limits} }

func NewDefault() *Engine { return New(DefaultLimits()) }

func (e *Engine) Scan(ctx context.Context, cfg Config) (model.Report, error) {
	if e.limits.ScanTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, e.limits.ScanTimeout)
		defer cancel()
	}
	started := time.Now().UTC()
	report := model.Report{
		SchemaVersion: model.SchemaVersion,
		Tool:          model.ToolInfo{Name: "WebCyber", Version: Version},
		Scan: model.ScanInfo{
			ID:        model.NewScanID(),
			Type:      cfg.Type,
			Target:    cfg.Target,
			Profile:   cfg.Profile,
			Status:    "running",
			StartedAt: started,
		},
		Findings: []model.Finding{},
		Modules:  []model.ModuleResult{},
	}

	if !cfg.Type.Valid() {
		return finish(report, started, "failed"), fmt.Errorf("unsupported scan type %q", cfg.Type)
	}
	if !cfg.Profile.Valid() {
		return finish(report, started, "failed"), fmt.Errorf("unsupported profile %q", cfg.Profile)
	}
	if cfg.Target == "" {
		return finish(report, started, "failed"), errors.New("target must not be empty")
	}

	var err error
	switch cfg.Type {
	case model.ScanTypeWeb:
		err = e.scanWeb(ctx, cfg, &report)
	case model.ScanTypeSource:
		err = e.scanSource(ctx, cfg, &report)
	case model.ScanTypeMobile:
		err = e.scanMobile(ctx, cfg, &report)
	case model.ScanTypeDesktop:
		err = e.scanDesktop(ctx, cfg, &report)
	}
	if err != nil && (errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled)) {
		report.Modules = append(report.Modules, model.ModuleResult{Name: "scan-budget", Status: model.ModuleError, Summary: "The scan stopped before all modules completed.", Errors: []string{err.Error()}})
	}

	report.Findings = model.NormalizeFindings(report.Findings)
	report.Summary = model.BuildSummary(report.Findings)
	status := "completed"
	if err != nil {
		status = "failed"
	} else {
		for _, module := range report.Modules {
			if module.Status == model.ModulePartial || module.Status == model.ModuleError {
				status = "partial"
				break
			}
		}
	}
	return finish(report, started, status), err
}

func finish(report model.Report, started time.Time, status string) model.Report {
	finished := time.Now().UTC()
	report.Scan.Status = status
	report.Scan.FinishedAt = finished
	report.Scan.DurationMS = finished.Sub(started).Milliseconds()
	if report.Findings == nil {
		report.Findings = []model.Finding{}
	}
	if report.Modules == nil {
		report.Modules = []model.ModuleResult{}
	}
	return report
}

func appendFinding(report *model.Report, finding model.Finding) {
	result := report.AddFinding(finding, maxReportFindings)
	if result != model.FindingCapped {
		return
	}
	const limitation = "Finding output stopped at the safety limit of 2000 records; narrow the target or split the scan for full coverage."
	for _, existing := range report.Limitations {
		if existing == limitation {
			return
		}
	}
	report.Limitations = append(report.Limitations, limitation)
	report.Modules = append(report.Modules, model.ModuleResult{
		Name:        "finding-output",
		Status:      model.ModulePartial,
		Summary:     "Unique findings exceeded the bounded report capacity.",
		ItemsSeen:   maxReportFindings,
		Limitations: []string{limitation},
	})
}
