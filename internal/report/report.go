// Package report serializes normalized WebCyber reports.
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"sort"
	"strings"

	"github.com/webcyber/webcyber/internal/model"
)

type Format string

const (
	FormatJSON  Format = "json"
	FormatSARIF Format = "sarif"
)

func (f Format) Valid() bool { return f == FormatJSON || f == FormatSARIF }

func Write(w io.Writer, format Format, input model.Report) error {
	input.Findings = model.NormalizeFindings(input.Findings)
	input.Summary = model.BuildSummary(input.Findings)
	switch format {
	case FormatJSON:
		return writeJSON(w, input)
	case FormatSARIF:
		return writeSARIF(w, input)
	default:
		return fmt.Errorf("unsupported report format %q", format)
	}
}

func writeJSON(w io.Writer, input model.Report) error {
	encoder := json.NewEncoder(w)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	return encoder.Encode(input)
}

type sarifLog struct {
	Version string     `json:"version"`
	Schema  string     `json:"$schema"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool        sarifTool         `json:"tool"`
	Invocations []sarifInvocation `json:"invocations"`
	Results     []sarifResult     `json:"results"`
	Properties  map[string]any    `json:"properties,omitempty"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	InformationURI string      `json:"informationUri,omitempty"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID                   string            `json:"id"`
	Name                 string            `json:"name,omitempty"`
	ShortDescription     sarifMessage      `json:"shortDescription"`
	FullDescription      sarifMessage      `json:"fullDescription"`
	Help                 sarifMessage      `json:"help,omitempty"`
	DefaultConfiguration map[string]string `json:"defaultConfiguration"`
	Properties           map[string]any    `json:"properties,omitempty"`
}

type sarifInvocation struct {
	ExecutionSuccessful bool           `json:"executionSuccessful"`
	Properties          map[string]any `json:"properties,omitempty"`
}

type sarifResult struct {
	RuleID              string            `json:"ruleId"`
	Level               string            `json:"level"`
	Message             sarifMessage      `json:"message"`
	Locations           []sarifLocation   `json:"locations,omitempty"`
	PartialFingerprints map[string]string `json:"partialFingerprints"`
	Properties          map[string]any    `json:"properties,omitempty"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
	Region           *sarifRegion          `json:"region,omitempty"`
}

type sarifArtifactLocation struct {
	URI string `json:"uri"`
}

type sarifRegion struct {
	StartLine int `json:"startLine"`
}

func writeSARIF(w io.Writer, input model.Report) error {
	rulesByID := make(map[string]sarifRule)
	results := make([]sarifResult, 0, len(input.Findings))
	for _, finding := range input.Findings {
		finding = model.CanonicalFinding(finding)
		if _, exists := rulesByID[finding.RuleID]; !exists {
			rulesByID[finding.RuleID] = sarifRule{
				ID:                   finding.RuleID,
				Name:                 sarifRuleName(finding.RuleID),
				ShortDescription:     sarifMessage{Text: finding.Title},
				FullDescription:      sarifMessage{Text: finding.Description},
				Help:                 sarifMessage{Text: finding.Remediation},
				DefaultConfiguration: map[string]string{"level": sarifLevel(finding.Severity)},
				Properties:           ruleProperties(finding),
			}
		}
		properties := map[string]any{
			"severity":    finding.Severity,
			"module":      finding.Module,
			"confidence":  finding.Confidence,
			"remediation": finding.Remediation,
		}
		if finding.CWE != "" {
			properties["cwe"] = finding.CWE
		}
		if finding.CVE != "" {
			properties["cve"] = finding.CVE
		}
		if finding.Evidence.Snippet != "" {
			properties["evidence"] = finding.Evidence.Snippet
		}
		for key, value := range finding.Evidence.Details {
			properties["evidence."+key] = value
		}
		result := sarifResult{
			RuleID:              finding.RuleID,
			Level:               sarifLevel(finding.Severity),
			Message:             sarifMessage{Text: finding.Title + ": " + finding.Description},
			PartialFingerprints: map[string]string{"webcyber/v1": finding.Fingerprint},
			Properties:          properties,
		}
		if location := sarifFindingLocation(finding); location != nil {
			result.Locations = []sarifLocation{*location}
		}
		results = append(results, result)
	}
	ruleIDs := make([]string, 0, len(rulesByID))
	for id := range rulesByID {
		ruleIDs = append(ruleIDs, id)
	}
	sort.Strings(ruleIDs)
	rules := make([]sarifRule, 0, len(ruleIDs))
	for _, id := range ruleIDs {
		rules = append(rules, rulesByID[id])
	}
	log := sarifLog{
		Version: "2.1.0",
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Runs: []sarifRun{{
			Tool:        sarifTool{Driver: sarifDriver{Name: input.Tool.Name, Version: input.Tool.Version, InformationURI: "https://github.com/webcyber/webcyber", Rules: rules}},
			Invocations: []sarifInvocation{{ExecutionSuccessful: input.Scan.Status != "failed", Properties: map[string]any{"scan_id": input.Scan.ID, "scan_type": input.Scan.Type, "profile": input.Scan.Profile, "status": input.Scan.Status}}},
			Results:     results,
			Properties:  map[string]any{"schema_version": input.SchemaVersion, "target": input.Scan.Target, "module_statuses": input.Modules, "limitations": input.Limitations},
		}},
	}
	encoder := json.NewEncoder(w)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	return encoder.Encode(log)
}

func sarifLevel(severity model.Severity) string {
	switch severity {
	case model.SeverityCritical, model.SeverityHigh:
		return "error"
	case model.SeverityMedium, model.SeverityLow:
		return "warning"
	default:
		return "note"
	}
}

func ruleProperties(finding model.Finding) map[string]any {
	properties := map[string]any{
		"module":            finding.Module,
		"security-severity": securitySeverity(finding.Severity),
		"tags":              []string{"security", finding.Module},
	}
	if finding.CWE != "" {
		properties["cwe"] = finding.CWE
	}
	return properties
}

func securitySeverity(severity model.Severity) string {
	switch severity {
	case model.SeverityCritical:
		return "9.5"
	case model.SeverityHigh:
		return "8.0"
	case model.SeverityMedium:
		return "5.5"
	case model.SeverityLow:
		return "3.0"
	default:
		return "0.0"
	}
}

func sarifRuleName(ruleID string) string {
	parts := strings.FieldsFunc(ruleID, func(r rune) bool { return r == '.' || r == '-' || r == '_' })
	for index := range parts {
		if parts[index] != "" {
			parts[index] = strings.ToUpper(parts[index][:1]) + parts[index][1:]
		}
	}
	return strings.Join(parts, "")
}

func sarifFindingLocation(finding model.Finding) *sarifLocation {
	uri := finding.Evidence.Location
	if uri == "" {
		uri = finding.Evidence.URL
	}
	if uri == "" {
		return nil
	}
	location := &sarifLocation{PhysicalLocation: sarifPhysicalLocation{ArtifactLocation: sarifArtifactLocation{URI: sarifArtifactURI(uri)}}}
	if finding.Evidence.Line > 0 {
		location.PhysicalLocation.Region = &sarifRegion{StartLine: finding.Evidence.Line}
	}
	return location
}

func sarifArtifactURI(raw string) string {
	normalized := strings.ReplaceAll(raw, "\\", "/")
	if parsed, err := url.Parse(normalized); err == nil && parsed.Scheme != "" && !(len(parsed.Scheme) == 1 && len(normalized) > 2 && normalized[1] == ':') {
		if parsed.RawQuery != "" {
			if values, queryErr := url.ParseQuery(parsed.RawQuery); queryErr == nil {
				parsed.RawQuery = values.Encode()
			} else {
				parsed.RawQuery = ""
			}
		}
		return parsed.String()
	}
	if len(normalized) > 2 && normalized[1] == ':' {
		return (&url.URL{Scheme: "file", Path: "/" + normalized}).String()
	}
	return (&url.URL{Path: normalized}).String()
}
