package scan

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"unicode"

	"github.com/webcyber/webcyber/internal/model"
)

var (
	awsAccessKeyPattern  = regexp.MustCompile(`\b(?:AKIA|ASIA)[A-Z0-9]{16}\b`)
	jwtPattern           = regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b`)
	privateKeyPattern    = regexp.MustCompile(`-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----`)
	genericSecretPattern = regexp.MustCompile(`(?i)(api[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret|secret|password|passwd)\s*["']?\s*[:=]\s*["']?([A-Za-z0-9_./+@:=\-]{8,})`)

	electronChecks = []electronCheck{
		{regexp.MustCompile(`(?i)\bnodeIntegration\s*["']?\s*[:=]\s*true\b`), "source.electron.node-integration", "Electron nodeIntegration is enabled", model.SeverityHigh, "CWE-94", "Disable nodeIntegration for content that can render remote or untrusted data."},
		{regexp.MustCompile(`(?i)\bcontextIsolation\s*["']?\s*[:=]\s*false\b`), "source.electron.context-isolation", "Electron context isolation is disabled", model.SeverityHigh, "CWE-693", "Enable contextIsolation and expose a narrow API through a preload bridge."},
		{regexp.MustCompile(`(?i)\bwebSecurity\s*["']?\s*[:=]\s*false\b`), "source.electron.web-security", "Electron web security is disabled", model.SeverityCritical, "CWE-346", "Keep webSecurity enabled and fix the underlying origin or content restrictions."},
		{regexp.MustCompile(`(?i)\ballowRunningInsecureContent\s*["']?\s*[:=]\s*true\b`), "source.electron.insecure-content", "Electron allows insecure content", model.SeverityHigh, "CWE-319", "Disable allowRunningInsecureContent and serve every subresource over HTTPS."},
		{regexp.MustCompile(`(?i)\benableRemoteModule\s*["']?\s*[:=]\s*true\b`), "source.electron.remote-module", "Electron remote module is enabled", model.SeverityHigh, "CWE-749", "Disable the remote module and use explicit, validated IPC handlers."},
		{regexp.MustCompile(`(?i)\bsandbox\s*["']?\s*[:=]\s*false\b`), "source.electron.sandbox", "Electron renderer sandbox is disabled", model.SeverityMedium, "CWE-693", "Enable the renderer sandbox unless a documented compatibility requirement prevents it."},
	}
)

type electronCheck struct {
	pattern     *regexp.Regexp
	rule        string
	title       string
	severity    model.Severity
	cwe         string
	remediation string
}

type sourceStats struct {
	textFiles       int
	binaryFiles     int
	truncatedFiles  int
	readErrors      int
	bytesRead       int64
	manifestCount   int
	dependencyCount int
	electronFiles   int
	totalLimitHit   bool
}

func (e *Engine) scanSource(ctx context.Context, _ Config, report *model.Report) error {
	_, files, walk, err := collectFiles(report.Scan.Target, e.limits)
	if err != nil {
		report.Modules = append(report.Modules, model.ModuleResult{Name: "file-inventory", Status: model.ModuleError, Summary: "The source target could not be enumerated.", Errors: []string{err.Error()}})
		return err
	}
	stats := sourceStats{}
	secretFindings := 0
	electronFindings := 0
	dependencyFindings := 0

	for _, record := range files {
		if err := ctx.Err(); err != nil {
			return err
		}
		if stats.bytesRead >= e.limits.MaxTotalBytes {
			stats.totalLimitHit = true
			break
		}
		allowance := e.limits.MaxFileBytes
		if remaining := e.limits.MaxTotalBytes - stats.bytesRead; remaining < allowance {
			allowance = remaining
		}
		data, truncated, readErr := readLimitedFile(record, allowance)
		if readErr != nil {
			stats.readErrors++
			continue
		}
		stats.bytesRead += int64(len(data))
		if truncated {
			stats.truncatedFiles++
		}
		if isProbablyBinary(data) {
			stats.binaryFiles++
			continue
		}
		stats.textFiles++
		before := len(report.Findings)
		inspectSecrets(record.Relative, data, report)
		secretFindings += len(report.Findings) - before

		before = len(report.Findings)
		if isElectronCandidate(record.Relative) {
			stats.electronFiles++
			inspectElectron(record.Relative, data, report)
		}
		electronFindings += len(report.Findings) - before

		before = len(report.Findings)
		manifests, dependencies := inspectDependencyManifest(record.Relative, data, report)
		stats.manifestCount += manifests
		stats.dependencyCount += dependencies
		dependencyFindings += len(report.Findings) - before
	}

	limited := walk.LimitHit || stats.totalLimitHit || stats.truncatedFiles > 0 || stats.readErrors > 0
	status := model.ModuleComplete
	limitations := []string(nil)
	if limited {
		status = model.ModulePartial
		limitations = append(limitations, "One or more path, count, size, or read limits prevented full coverage.")
	}
	report.Modules = append(report.Modules,
		model.ModuleResult{Name: "file-inventory", Status: status, Summary: fmt.Sprintf("Enumerated %d regular files; skipped %d symbolic links and %d unreadable or unsupported entries.", len(files), walk.Symlinks, walk.FilesSkipped+stats.readErrors), ItemsSeen: len(files), Limitations: limitations},
		model.ModuleResult{Name: "secret-detection", Status: status, Summary: fmt.Sprintf("Inspected %d text files and produced %d redacted candidate findings.", stats.textFiles, secretFindings), ItemsSeen: stats.textFiles, Limitations: limitations},
		model.ModuleResult{Name: "dependency-inventory", Status: model.ModulePartial, Summary: fmt.Sprintf("Found %d dependency manifests describing approximately %d dependencies; %d unsafe-specification findings were produced.", stats.manifestCount, stats.dependencyCount, dependencyFindings), ItemsSeen: stats.manifestCount, Limitations: []string{"Offline MVP inventories manifests but does not yet query OSV/CVE or license databases."}},
		model.ModuleResult{Name: "electron-configuration", Status: status, Summary: fmt.Sprintf("Inspected %d Electron-relevant text files and produced %d findings.", stats.electronFiles, electronFindings), ItemsSeen: stats.electronFiles, Limitations: limitations},
	)
	report.Limitations = append(report.Limitations,
		"Static matching does not execute project code, install dependencies, invoke build scripts, or resolve dynamic configuration.",
		"Secret values are never included in evidence; candidates require owner verification and credential rotation when confirmed.",
	)
	return nil
}

func inspectSecrets(path string, data []byte, report *model.Report) {
	lines := strings.Split(string(data), "\n")
	for index, rawLine := range lines {
		line := strings.TrimSpace(rawLine)
		if len(line) > 20_000 {
			line = line[:20_000]
		}
		if awsAccessKeyPattern.MatchString(line) {
			appendSecretFinding(report, "source.secret.aws-access-key", "Possible AWS access key", model.SeverityCritical, "CWE-798", path, index+1, "AWS access key identifier")
		}
		if jwtPattern.MatchString(line) {
			appendSecretFinding(report, "source.secret.jwt", "Possible hardcoded JSON Web Token", model.SeverityHigh, "CWE-798", path, index+1, "JSON Web Token")
		}
		if privateKeyPattern.MatchString(line) {
			appendSecretFinding(report, "source.secret.private-key", "Private key material is present", model.SeverityCritical, "CWE-321", path, index+1, "private key block")
		}
		matches := genericSecretPattern.FindAllStringSubmatch(line, -1)
		for _, match := range matches {
			if len(match) < 3 || likelyPlaceholder(match[2]) || entropy(match[2]) < 2.6 {
				continue
			}
			appendSecretFinding(report, "source.secret.generic", "Possible hardcoded secret", model.SeverityHigh, "CWE-798", path, index+1, strings.ToLower(match[1]))
		}
	}
}

func appendSecretFinding(report *model.Report, rule, title string, severity model.Severity, cwe, path string, line int, kind string) {
	report.Findings = append(report.Findings, model.Finding{
		RuleID: rule, Module: "secret-detection", Title: title, Severity: severity, Confidence: "medium", CWE: cwe,
		Description: "Static analysis found text shaped like credential material. The value was redacted before reporting.",
		Remediation: "Verify the candidate, revoke and rotate it if real, remove it from history, and load credentials from an approved secret store.",
		Evidence:    model.Evidence{Location: path, Line: line, Snippet: "[REDACTED]", Details: map[string]string{"candidate_type": kind}},
	})
}

func likelyPlaceholder(value string) bool {
	lower := strings.ToLower(strings.TrimSpace(value))
	for _, marker := range []string{"example", "sample", "placeholder", "changeme", "change_me", "your_", "<", "${", "process.env", "getenv", "xxxxxxxx"} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	allSame := true
	for i := 1; i < len(value); i++ {
		if value[i] != value[0] {
			allSame = false
			break
		}
	}
	return allSame
}

func entropy(value string) float64 {
	if value == "" {
		return 0
	}
	counts := make(map[rune]int)
	total := 0
	for _, r := range value {
		counts[r]++
		total++
	}
	result := 0.0
	for _, count := range counts {
		p := float64(count) / float64(total)
		result -= p * math.Log2(p)
	}
	return result
}

func isElectronCandidate(path string) bool {
	base := strings.ToLower(filepath.Base(path))
	ext := strings.ToLower(filepath.Ext(path))
	if base == "package.json" || strings.Contains(base, "electron") || strings.Contains(base, "preload") || strings.Contains(base, "main") {
		return true
	}
	switch ext {
	case ".js", ".cjs", ".mjs", ".jsx", ".ts", ".tsx", ".json":
		return true
	default:
		return false
	}
}

func inspectElectron(path string, data []byte, report *model.Report) {
	lines := strings.Split(string(data), "\n")
	for index, line := range lines {
		for _, check := range electronChecks {
			if check.pattern.MatchString(line) {
				report.Findings = append(report.Findings, model.Finding{
					RuleID: check.rule, Module: "electron-configuration", Title: check.title, Severity: check.severity, Confidence: "high", CWE: check.cwe,
					Description: "A security-sensitive Electron preference is configured to an unsafe literal value.", Remediation: check.remediation,
					Evidence: model.Evidence{Location: path, Line: index + 1, Snippet: check.pattern.FindString(line)},
				})
			}
		}
	}
}

var dependencyManifestNames = map[string]struct{}{
	"package.json": {}, "package-lock.json": {}, "npm-shrinkwrap.json": {}, "yarn.lock": {}, "pnpm-lock.yaml": {},
	"requirements.txt": {}, "pipfile": {}, "pipfile.lock": {}, "pyproject.toml": {}, "poetry.lock": {},
	"go.mod": {}, "go.sum": {}, "cargo.toml": {}, "cargo.lock": {}, "pom.xml": {}, "build.gradle": {}, "build.gradle.kts": {},
	"composer.json": {}, "composer.lock": {}, "gemfile": {}, "gemfile.lock": {},
}

func inspectDependencyManifest(path string, data []byte, report *model.Report) (int, int) {
	base := strings.ToLower(filepath.Base(path))
	if _, ok := dependencyManifestNames[base]; !ok {
		return 0, 0
	}
	if base == "package.json" {
		return 1, inspectPackageJSON(path, data, report)
	}
	if base == "requirements.txt" {
		return 1, inspectRequirements(path, data, report)
	}
	return 1, approximateManifestEntries(base, data)
}

func inspectPackageJSON(path string, data []byte, report *model.Report) int {
	var document struct {
		Dependencies         map[string]string `json:"dependencies"`
		DevDependencies      map[string]string `json:"devDependencies"`
		OptionalDependencies map[string]string `json:"optionalDependencies"`
		PeerDependencies     map[string]string `json:"peerDependencies"`
	}
	if err := json.Unmarshal(data, &document); err != nil {
		return 0
	}
	groups := []map[string]string{document.Dependencies, document.DevDependencies, document.OptionalDependencies, document.PeerDependencies}
	count := 0
	for _, dependencies := range groups {
		names := make([]string, 0, len(dependencies))
		for name := range dependencies {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			count++
			specification := strings.TrimSpace(dependencies[name])
			if unsafeDependencySpecification(specification) {
				report.Findings = append(report.Findings, model.Finding{
					RuleID: "source.dependency.unbounded-specification", Module: "dependency-inventory", Title: "Dependency uses an unsafe or non-reproducible specification", Severity: model.SeverityMedium, Confidence: "high", CWE: "CWE-829",
					Description: "A dependency is sourced from a floating tag, wildcard, URL, Git repository, or local path.", Remediation: "Use a reviewed registry release and a lockfile with integrity metadata.",
					Evidence: model.Evidence{Location: path, Details: map[string]string{"dependency": name, "specification_type": dependencySpecificationType(specification)}},
				})
			}
		}
	}
	return count
}

func unsafeDependencySpecification(value string) bool {
	lower := strings.ToLower(strings.TrimSpace(value))
	return lower == "" || lower == "*" || lower == "latest" || strings.HasPrefix(lower, "git") || strings.HasPrefix(lower, "http:") || strings.HasPrefix(lower, "https:") || strings.HasPrefix(lower, "file:") || strings.HasPrefix(lower, "link:") || strings.HasPrefix(lower, "github:")
}

func dependencySpecificationType(value string) string {
	lower := strings.ToLower(strings.TrimSpace(value))
	switch {
	case lower == "", lower == "*", lower == "latest":
		return "floating"
	case strings.HasPrefix(lower, "git"), strings.HasPrefix(lower, "github:"):
		return "git"
	case strings.HasPrefix(lower, "http:"):
		return "http-url"
	case strings.HasPrefix(lower, "https:"):
		return "https-url"
	case strings.HasPrefix(lower, "file:"), strings.HasPrefix(lower, "link:"):
		return "local-path"
	default:
		return "other"
	}
}

func inspectRequirements(path string, data []byte, report *model.Report) int {
	count := 0
	for index, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "-") {
			continue
		}
		count++
		if !strings.Contains(line, "==") || strings.Contains(line, "://") || strings.HasPrefix(line, "git+") {
			name := line
			if position := strings.IndexAny(name, "<>=!~ @;"); position >= 0 {
				name = name[:position]
			}
			report.Findings = append(report.Findings, model.Finding{
				RuleID: "source.dependency.python-unpinned", Module: "dependency-inventory", Title: "Python dependency is not exactly pinned", Severity: model.SeverityLow, Confidence: "high", CWE: "CWE-829",
				Description: "A direct Python requirement is not fixed to an exact registry version.", Remediation: "Pin reviewed direct dependencies and use a hash-locked transitive dependency workflow.",
				Evidence: model.Evidence{Location: path, Line: index + 1, Details: map[string]string{"dependency": strings.TrimFunc(name, unicode.IsSpace)}},
			})
		}
	}
	return count
}

func approximateManifestEntries(base string, data []byte) int {
	text := string(data)
	switch base {
	case "go.mod":
		return strings.Count(text, "\n\t") + strings.Count(text, "require ")
	case "yarn.lock", "pnpm-lock.yaml", "cargo.lock", "go.sum", "gemfile.lock", "composer.lock", "poetry.lock", "pipfile.lock", "package-lock.json", "npm-shrinkwrap.json":
		return strings.Count(text, "\n")
	default:
		return 0
	}
}
