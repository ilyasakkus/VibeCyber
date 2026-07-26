package scan

import (
	"archive/zip"
	"bytes"
	"context"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/webcyber/webcyber/internal/model"
)

type mobileStats struct {
	archives         int
	manifestFiles    int
	binaryManifests  int
	configFindings   int
	archiveLimitHit  bool
	archiveParseErrs int
	readLimitHit     bool
	bytesRead        int64
}

func (e *Engine) scanMobile(ctx context.Context, _ Config, report *model.Report) error {
	tree, err := collectFiles(report.Scan.Target, e.limits)
	if err != nil {
		report.Modules = append(report.Modules, model.ModuleResult{Name: "artifact-metadata", Status: model.ModuleError, Summary: "The mobile target could not be opened inside a bounded filesystem root.", Errors: []string{err.Error()}})
		return err
	}
	defer tree.Close()
	metadata, hashLimited, err := inspectTargetMetadata(tree, e.limits.MaxArchiveTotalBytes)
	if err != nil {
		report.Modules = append(report.Modules, model.ModuleResult{Name: "artifact-metadata", Status: model.ModuleError, Summary: "The mobile target metadata could not be read.", Errors: []string{err.Error()}})
		return err
	}
	metadataStatus := model.ModuleComplete
	metadataLimits := []string(nil)
	if hashLimited {
		metadataStatus = model.ModulePartial
		metadataLimits = []string{"SHA-256 was not published because the bounded stable-read requirement was not met."}
	}
	metadataModuleIndex := len(report.Modules)
	report.Modules = append(report.Modules, model.ModuleResult{Name: "artifact-metadata", Status: metadataStatus, Summary: "Collected static artifact type, size, and bounded hash metadata.", ItemsSeen: 1, Metadata: metadata, Limitations: metadataLimits})
	defer func() {
		if !invalidatePublishedTargetHashIfChanged(tree, metadata, e.limits.MaxArchiveTotalBytes) {
			return
		}
		module := &report.Modules[metadataModuleIndex]
		module.Status = model.ModulePartial
		const limitation = "The target changed or could not be reverified after analysis, so its previously computed SHA-256 was invalidated."
		module.Limitations = append(module.Limitations, limitation)
	}()

	files, walk := tree.Files, tree.Stats
	stats := mobileStats{}
	for _, record := range files {
		if err := ctx.Err(); err != nil {
			return err
		}
		lower := strings.ToLower(record.Relative)
		if isMobileArchive(lower) && stats.archives >= 20 {
			stats.archiveLimitHit = true
			continue
		}
		if isMobileArchive(lower) {
			stats.archives++
			archive, archiveErr := inspectZIP(record, record.Relative, e.limits, report, func(entry *zip.File, name string) error {
				entryLower := strings.ToLower(name)
				if !strings.HasSuffix(entryLower, "androidmanifest.xml") && !strings.HasSuffix(entryLower, "info.plist") {
					return nil
				}
				remaining := e.limits.MaxTotalBytes - stats.bytesRead
				if remaining <= 0 {
					stats.readLimitHit = true
					return fmt.Errorf("mobile manifest byte budget exhausted")
				}
				limit := e.limits.MaxFileBytes
				if remaining < limit {
					limit = remaining
				}
				data, truncated, readErr := readArchiveEntry(entry, limit)
				if readErr != nil || truncated {
					stats.readLimitHit = true
					return readErr
				}
				stats.bytesRead += int64(len(data))
				stats.manifestFiles++
				before := len(report.Findings)
				inspectMobileConfiguration(record.Relative+"!/"+name, data, report, &stats)
				stats.configFindings += len(report.Findings) - before
				return nil
			})
			if archiveErr != nil {
				stats.archiveParseErrs++
				continue
			}
			if archive.LimitHit {
				stats.archiveLimitHit = true
			}
			continue
		}
		base := strings.ToLower(filepath.Base(record.Relative))
		if base == "androidmanifest.xml" || base == "info.plist" {
			remaining := e.limits.MaxTotalBytes - stats.bytesRead
			if remaining <= 0 {
				stats.readLimitHit = true
				continue
			}
			limit := e.limits.MaxFileBytes
			if remaining < limit {
				limit = remaining
			}
			data, truncated, readErr := readLimitedFile(record, limit)
			if readErr != nil || truncated {
				stats.readLimitHit = true
				continue
			}
			stats.bytesRead += int64(len(data))
			stats.manifestFiles++
			before := len(report.Findings)
			inspectMobileConfiguration(record.Relative, data, report, &stats)
			stats.configFindings += len(report.Findings) - before
		}
	}

	archiveStatus := model.ModuleSkipped
	archiveSummary := "No APK, IPA, AAB, or ZIP container was present in the bounded target inventory."
	archiveLimitations := []string(nil)
	archiveErrors := []string(nil)
	if stats.archives > 0 {
		archiveStatus = model.ModuleComplete
		archiveSummary = fmt.Sprintf("Inspected %d mobile ZIP containers without extracting files.", stats.archives)
		if stats.archiveLimitHit || stats.archiveParseErrs > 0 {
			archiveStatus = model.ModulePartial
		}
		if stats.archiveLimitHit {
			archiveLimitations = []string{"At least one archive exceeded entry, expansion, or compression-ratio limits."}
		}
		if stats.archiveParseErrs > 0 {
			archiveErrors = []string{"One or more mobile ZIP containers were malformed or use an unsupported structure."}
		}
	}
	configStatus := model.ModuleComplete
	configLimits := []string(nil)
	if walk.LimitHit || walk.Symlinks > 0 || walk.FilesSkipped > 0 || stats.readLimitHit || stats.binaryManifests > 0 || stats.archiveParseErrs > 0 {
		configStatus = model.ModulePartial
		if stats.binaryManifests > 0 {
			configLimits = append(configLimits, "Binary Android XML was identified but not decoded by the dependency-free MVP.")
		}
		if stats.archiveParseErrs > 0 {
			configLimits = append(configLimits, "Manifest coverage was reduced because one or more mobile containers were malformed or unsupported.")
		}
		if walk.LimitHit || walk.Symlinks > 0 || walk.FilesSkipped > 0 || stats.readLimitHit {
			configLimits = append(configLimits, "One or more symlink, file, path, or read boundaries reduced configuration coverage.")
		}
	}
	report.Modules = append(report.Modules,
		model.ModuleResult{Name: "archive-security", Status: archiveStatus, Summary: archiveSummary, ItemsSeen: stats.archives, Limitations: archiveLimitations, Errors: archiveErrors},
		model.ModuleResult{Name: "mobile-configuration", Status: configStatus, Summary: fmt.Sprintf("Inspected %d mobile manifest/property files and produced %d findings.", stats.manifestFiles, stats.configFindings), ItemsSeen: stats.manifestFiles, Limitations: configLimits},
		model.ModuleResult{Name: "mobile-reverse-engineering", Status: model.ModulePartial, Summary: "Recorded the artifact for a future isolated APK/IPA reverse-engineering worker.", Limitations: []string{"The built-in MVP does not invoke jadx, baksmali, codesign, or MobSF and does not execute the app."}},
	)
	return nil
}

func isMobileArchive(path string) bool {
	ext := strings.ToLower(filepath.Ext(path))
	return ext == ".apk" || ext == ".ipa" || ext == ".aab" || ext == ".apks" || ext == ".xapk" || ext == ".zip"
}

var mobileConfigurationChecks = []struct {
	pattern     *regexp.Regexp
	rule        string
	title       string
	severity    model.Severity
	cwe         string
	description string
	remediation string
}{
	{regexp.MustCompile(`(?i)android:allowBackup\s*=\s*["']true["']`), "mobile.android.backup-enabled", "Android application backup is enabled", model.SeverityMedium, "CWE-530", "Application data may be included in platform backup flows.", "Disable allowBackup unless backup is explicitly required and sensitive data is excluded."},
	{regexp.MustCompile(`(?i)android:debuggable\s*=\s*["']true["']`), "mobile.android.debuggable", "Android release is debuggable", model.SeverityHigh, "CWE-489", "The manifest enables application debugging.", "Disable debuggable in release builds and enforce this in the build pipeline."},
	{regexp.MustCompile(`(?i)android:usesCleartextTraffic\s*=\s*["']true["']`), "mobile.android.cleartext", "Android cleartext traffic is allowed", model.SeverityHigh, "CWE-319", "The application permits unencrypted network traffic.", "Disable cleartext traffic and use a restrictive Network Security Configuration."},
	{regexp.MustCompile(`(?is)<key>\s*NSAllowsArbitraryLoads\s*</key>\s*<true\s*/>`), "mobile.ios.arbitrary-loads", "iOS App Transport Security allows arbitrary loads", model.SeverityHigh, "CWE-319", "The property list broadly disables App Transport Security restrictions.", "Remove NSAllowsArbitraryLoads and define only narrowly scoped, justified exceptions."},
	{regexp.MustCompile(`(?is)<key>\s*UIFileSharingEnabled\s*</key>\s*<true\s*/>`), "mobile.ios.file-sharing", "iOS document file sharing is enabled", model.SeverityLow, "CWE-922", "The app exposes its Documents directory through file sharing.", "Disable file sharing unless required and keep sensitive data outside shared containers."},
}

var exportedComponentPattern = regexp.MustCompile(`(?is)<(activity|service|receiver|provider)\b[^>]*android:exported\s*=\s*["']true["'][^>]*>`)

func inspectMobileConfiguration(path string, data []byte, report *model.Report, stats *mobileStats) {
	if isProbablyBinary(data) || bytes.HasPrefix(data, []byte("bplist")) {
		stats.binaryManifests++
		return
	}
	text := string(data)
	for _, check := range mobileConfigurationChecks {
		for _, location := range check.pattern.FindAllStringIndex(text, -1) {
			appendFinding(report, model.Finding{
				RuleID: check.rule, Module: "mobile-configuration", Title: check.title, Severity: check.severity, Confidence: "high", CWE: check.cwe,
				Description: check.description, Remediation: check.remediation,
				Evidence: model.Evidence{Location: path, Line: lineAt(text, location[0]), Snippet: check.pattern.FindString(text[location[0]:location[1]])},
			})
		}
	}
	for occurrence, match := range exportedComponentPattern.FindAllStringIndex(text, -1) {
		tag := text[match[0]:match[1]]
		if strings.Contains(strings.ToLower(tag), "android:permission") {
			continue
		}
		component := "component"
		if groups := exportedComponentPattern.FindStringSubmatch(tag); len(groups) > 1 {
			component = strings.ToLower(groups[1])
		}
		appendFinding(report, model.Finding{
			RuleID: "mobile.android.unprotected-exported-component", Module: "mobile-configuration", Title: "Android component is exported without an inline permission", Severity: model.SeverityHigh, Confidence: "medium", CWE: "CWE-926",
			Description: "An exported Android component does not declare a permission on the same manifest element.", Remediation: "Set exported=false when external access is unnecessary, or require a signature-level permission and validate all inputs.",
			Evidence: model.Evidence{Location: path, Line: lineAt(text, match[0]), Snippet: "<" + component + " ... android:exported=\"true\" ...>", Details: map[string]string{"component_type": component, "occurrence": fmt.Sprintf("%d", occurrence+1)}},
		})
	}
}

func lineAt(text string, byteOffset int) int {
	if byteOffset <= 0 {
		return 1
	}
	return strings.Count(text[:byteOffset], "\n") + 1
}
