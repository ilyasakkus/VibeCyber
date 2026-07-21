// Package model contains the stable, scanner-independent report model.
package model

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"
)

const SchemaVersion = "1.0"

type ScanType string

const (
	ScanTypeWeb     ScanType = "web"
	ScanTypeSource  ScanType = "source"
	ScanTypeMobile  ScanType = "mobile"
	ScanTypeDesktop ScanType = "desktop"
)

func (s ScanType) Valid() bool {
	switch s {
	case ScanTypeWeb, ScanTypeSource, ScanTypeMobile, ScanTypeDesktop:
		return true
	default:
		return false
	}
}

type Profile string

const (
	ProfileObserve Profile = "observe"
	ProfileSafe    Profile = "safe"
)

func (p Profile) Valid() bool { return p == ProfileObserve || p == ProfileSafe }

type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

type ModuleStatus string

const (
	ModuleComplete ModuleStatus = "complete"
	ModulePartial  ModuleStatus = "partial"
	ModuleSkipped  ModuleStatus = "skipped"
	ModuleError    ModuleStatus = "error"
)

type Evidence struct {
	Location string            `json:"location,omitempty"`
	Line     int               `json:"line,omitempty"`
	URL      string            `json:"url,omitempty"`
	Snippet  string            `json:"snippet,omitempty"`
	Details  map[string]string `json:"details,omitempty"`
}

type Finding struct {
	RuleID      string   `json:"rule_id"`
	Fingerprint string   `json:"fingerprint"`
	Module      string   `json:"module"`
	Title       string   `json:"title"`
	Severity    Severity `json:"severity"`
	Confidence  string   `json:"confidence,omitempty"`
	CWE         string   `json:"cwe,omitempty"`
	CVE         string   `json:"cve,omitempty"`
	Description string   `json:"description"`
	Remediation string   `json:"remediation,omitempty"`
	Evidence    Evidence `json:"evidence,omitempty"`
	References  []string `json:"references,omitempty"`
}

type ModuleResult struct {
	Name        string            `json:"name"`
	Status      ModuleStatus      `json:"status"`
	Summary     string            `json:"summary"`
	ItemsSeen   int               `json:"items_seen,omitempty"`
	Metadata    map[string]string `json:"metadata,omitempty"`
	Limitations []string          `json:"limitations,omitempty"`
	Errors      []string          `json:"errors,omitempty"`
}

type ScanInfo struct {
	ID         string    `json:"id"`
	Type       ScanType  `json:"type"`
	Target     string    `json:"target"`
	Profile    Profile   `json:"profile"`
	Status     string    `json:"status"`
	StartedAt  time.Time `json:"started_at"`
	FinishedAt time.Time `json:"finished_at"`
	DurationMS int64     `json:"duration_ms"`
}

type Summary struct {
	Total    int `json:"total"`
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	Info     int `json:"info"`
}

type ToolInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type Report struct {
	SchemaVersion string         `json:"schema_version"`
	Tool          ToolInfo       `json:"tool"`
	Scan          ScanInfo       `json:"scan"`
	Summary       Summary        `json:"summary"`
	Modules       []ModuleResult `json:"modules"`
	Findings      []Finding      `json:"findings"`
	Limitations   []string       `json:"limitations,omitempty"`
}

// NewScanID returns a non-identifying random scan identifier.
func NewScanID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return fmt.Sprintf("scan-%d", time.Now().UTC().UnixNano())
	}
	// UUID v4 layout, without taking a dependency for one identifier.
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// Fingerprint is stable across runs and deliberately excludes secret snippets.
func Fingerprint(f Finding) string {
	parts := []string{
		strings.ToLower(strings.TrimSpace(f.RuleID)),
		strings.ToLower(strings.TrimSpace(f.Module)),
		strings.TrimSpace(f.Evidence.Location),
		fmt.Sprintf("%d", f.Evidence.Line),
		strings.ToLower(strings.TrimSpace(f.Evidence.URL)),
	}
	sum := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return "sha256:" + hex.EncodeToString(sum[:])
}

// NormalizeFindings fills fingerprints, removes duplicates, and sorts output.
func NormalizeFindings(in []Finding) []Finding {
	unique := make(map[string]Finding, len(in))
	for _, finding := range in {
		if finding.Fingerprint == "" {
			finding.Fingerprint = Fingerprint(finding)
		}
		if _, exists := unique[finding.Fingerprint]; !exists {
			unique[finding.Fingerprint] = finding
		}
	}
	out := make([]Finding, 0, len(unique))
	for _, finding := range unique {
		out = append(out, finding)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if severityRank(out[i].Severity) != severityRank(out[j].Severity) {
			return severityRank(out[i].Severity) > severityRank(out[j].Severity)
		}
		if out[i].RuleID != out[j].RuleID {
			return out[i].RuleID < out[j].RuleID
		}
		if out[i].Evidence.Location != out[j].Evidence.Location {
			return out[i].Evidence.Location < out[j].Evidence.Location
		}
		return out[i].Evidence.Line < out[j].Evidence.Line
	})
	return out
}

func BuildSummary(findings []Finding) Summary {
	s := Summary{Total: len(findings)}
	for _, finding := range findings {
		switch finding.Severity {
		case SeverityCritical:
			s.Critical++
		case SeverityHigh:
			s.High++
		case SeverityMedium:
			s.Medium++
		case SeverityLow:
			s.Low++
		default:
			s.Info++
		}
	}
	return s
}

func severityRank(severity Severity) int {
	switch severity {
	case SeverityCritical:
		return 5
	case SeverityHigh:
		return 4
	case SeverityMedium:
		return 3
	case SeverityLow:
		return 2
	default:
		return 1
	}
}
