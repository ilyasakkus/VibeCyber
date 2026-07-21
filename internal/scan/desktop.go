package scan

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/webcyber/webcyber/internal/model"
)

type desktopStats struct {
	archives         int
	archiveLimitHit  bool
	electronFiles    int
	electronFindings int
	asars            int
	binaries         int
	binaryParsed     int
	binaryFormats    map[string]int
	readLimitHit     bool
}

func (e *Engine) scanDesktop(ctx context.Context, _ Config, report *model.Report) error {
	metadata, hashLimited, err := inspectTargetMetadata(report.Scan.Target, e.limits.MaxArchiveTotalBytes)
	if err != nil {
		report.Modules = append(report.Modules, model.ModuleResult{Name: "artifact-metadata", Status: model.ModuleError, Summary: "The desktop target metadata could not be read.", Errors: []string{err.Error()}})
		return err
	}
	metadataStatus := model.ModuleComplete
	metadataLimits := []string(nil)
	if hashLimited {
		metadataStatus = model.ModulePartial
		metadataLimits = []string{"SHA-256 was not computed because the target exceeds the bounded hashing limit."}
	}
	report.Modules = append(report.Modules, model.ModuleResult{Name: "artifact-metadata", Status: metadataStatus, Summary: "Collected static desktop artifact type, size, and bounded hash metadata.", ItemsSeen: 1, Metadata: metadata, Limitations: metadataLimits})

	_, files, walk, err := collectFiles(report.Scan.Target, e.limits)
	if err != nil {
		return err
	}
	stats := desktopStats{binaryFormats: make(map[string]int)}
	var bytesRead int64
	for _, record := range files {
		if err := ctx.Err(); err != nil {
			return err
		}
		lower := strings.ToLower(record.Relative)
		if strings.HasSuffix(lower, ".asar") {
			stats.asars++
		}
		if strings.HasSuffix(lower, ".zip") && stats.archives < 20 {
			stats.archives++
			archive, archiveErr := inspectZIP(record.Absolute, record.Relative, e.limits, report, nil)
			if archiveErr != nil || archive.LimitHit {
				stats.archiveLimitHit = true
			}
		}
		recognized, complete, format := inspectBinaryProtection(record, report)
		if recognized {
			stats.binaries++
			stats.binaryFormats[format]++
			if complete {
				stats.binaryParsed++
			}
		}
		if !isElectronCandidate(record.Relative) || bytesRead >= e.limits.MaxTotalBytes {
			continue
		}
		allowance := e.limits.MaxFileBytes
		if remaining := e.limits.MaxTotalBytes - bytesRead; remaining < allowance {
			allowance = remaining
		}
		data, truncated, readErr := readLimitedFile(record, allowance)
		if readErr != nil || truncated {
			stats.readLimitHit = true
			continue
		}
		bytesRead += int64(len(data))
		if isProbablyBinary(data) {
			continue
		}
		stats.electronFiles++
		before := len(report.Findings)
		inspectElectron(record.Relative, data, report)
		stats.electronFindings += len(report.Findings) - before
	}

	archiveStatus := model.ModuleSkipped
	archiveSummary := "No desktop ZIP container was found in the bounded inventory."
	if stats.archives > 0 {
		archiveStatus = model.ModuleComplete
		archiveSummary = fmt.Sprintf("Inspected %d ZIP containers without extraction.", stats.archives)
		if stats.archiveLimitHit {
			archiveStatus = model.ModulePartial
		}
	}
	electronStatus := model.ModuleComplete
	electronLimits := []string(nil)
	if stats.asars > 0 || stats.readLimitHit || walk.LimitHit {
		electronStatus = model.ModulePartial
		if stats.asars > 0 {
			electronLimits = append(electronLimits, fmt.Sprintf("Detected %d ASAR files; dependency-free MVP records but does not unpack ASAR.", stats.asars))
		}
		if stats.readLimitHit || walk.LimitHit {
			electronLimits = append(electronLimits, "File, depth, or byte limits reduced configuration coverage.")
		}
	}
	formatMetadata := make(map[string]string)
	for format, count := range stats.binaryFormats {
		formatMetadata[strings.ToLower(format)+"_count"] = fmt.Sprintf("%d", count)
	}
	report.Modules = append(report.Modules,
		model.ModuleResult{Name: "archive-security", Status: archiveStatus, Summary: archiveSummary, ItemsSeen: stats.archives},
		model.ModuleResult{Name: "electron-configuration", Status: electronStatus, Summary: fmt.Sprintf("Inspected %d Electron-relevant files and produced %d configuration findings.", stats.electronFiles, stats.electronFindings), ItemsSeen: stats.electronFiles, Limitations: electronLimits},
		model.ModuleResult{Name: "binary-protection", Status: model.ModulePartial, Summary: fmt.Sprintf("Recognized %d PE/ELF/Mach-O binaries and safely parsed bounded headers for %d.", stats.binaries, stats.binaryParsed), ItemsSeen: stats.binaries, Metadata: formatMetadata, Limitations: []string{"Header checks cover common ASLR/DEP/CFG, PIE, stack, and RELRO flags only; code signing, entitlements, packed binaries, fat Mach-O slices, and control-flow analysis require an isolated deep-analysis worker."}},
	)
	report.Limitations = append(report.Limitations, "Desktop analysis never launches the program, loads its libraries, mounts disk images, or invokes platform tools.")
	return nil
}

func desktopExtension(path string) string { return strings.ToLower(filepath.Ext(path)) }
