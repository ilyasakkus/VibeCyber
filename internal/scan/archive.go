package scan

import (
	"archive/zip"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/webcyber/webcyber/internal/model"
)

type archiveStats struct {
	Entries           int
	UncompressedBytes uint64
	Encrypted         int
	UnsafePaths       int
	SuspiciousRatios  int
	Symlinks          int
	LimitHit          bool
}

type archiveVisitor func(entry *zip.File, normalizedName string) error

func inspectZIP(filename, displayPath string, limits Limits, report *model.Report, visitor archiveVisitor) (archiveStats, error) {
	var stats archiveStats
	reader, err := zip.OpenReader(filename)
	if err != nil {
		return stats, fmt.Errorf("open ZIP archive: %w", err)
	}
	defer reader.Close()
	seen := make(map[string]struct{})
	for index, entry := range reader.File {
		if index >= limits.MaxArchiveEntries {
			stats.LimitHit = true
			break
		}
		stats.Entries++
		if ^uint64(0)-stats.UncompressedBytes < entry.UncompressedSize64 {
			stats.LimitHit = true
			break
		}
		stats.UncompressedBytes += entry.UncompressedSize64
		normalized, safe := safeArchiveName(entry.Name)
		if !safe {
			stats.UnsafePaths++
			report.Findings = append(report.Findings, model.Finding{
				RuleID: "archive.path-traversal", Module: "archive-security", Title: "Archive entry can escape the extraction directory", Severity: model.SeverityHigh, Confidence: "high", CWE: "CWE-22",
				Description: "A ZIP entry uses an absolute path, parent traversal, or drive-qualified name.", Remediation: "Reject the archive or normalize and boundary-check every destination before extraction.",
				Evidence: model.Evidence{Location: displayPath, Details: map[string]string{"entry": truncate(entry.Name, 200)}},
			})
			continue
		}
		if _, duplicate := seen[normalized]; duplicate {
			report.Findings = append(report.Findings, model.Finding{
				RuleID: "archive.duplicate-entry", Module: "archive-security", Title: "Archive contains duplicate normalized paths", Severity: model.SeverityMedium, Confidence: "high", CWE: "CWE-436",
				Description: "More than one ZIP record maps to the same normalized path, which can produce parser-dependent results.", Remediation: "Reject archives with duplicate normalized entry names.",
				Evidence: model.Evidence{Location: displayPath, Details: map[string]string{"entry": truncate(normalized, 200)}},
			})
		} else {
			seen[normalized] = struct{}{}
		}
		if entry.Flags&0x1 != 0 {
			stats.Encrypted++
			report.Findings = append(report.Findings, model.Finding{
				RuleID: "archive.encrypted-entry", Module: "archive-security", Title: "Encrypted archive entry was not inspected", Severity: model.SeverityInfo, Confidence: "high",
				Description: "The ZIP entry is encrypted, so its content cannot be statically inspected by the built-in scanner.", Remediation: "Provide an authorized, decrypted artifact in an isolated workspace for complete inspection.",
				Evidence: model.Evidence{Location: displayPath, Details: map[string]string{"entry": truncate(normalized, 200)}},
			})
		}
		if entry.Mode()&os.ModeSymlink != 0 {
			stats.Symlinks++
			report.Findings = append(report.Findings, model.Finding{
				RuleID: "archive.symbolic-link", Module: "archive-security", Title: "Archive contains a symbolic link", Severity: model.SeverityLow, Confidence: "high", CWE: "CWE-59",
				Description: "Unsafe extractors may follow a symlink in the archive and write outside the intended destination.", Remediation: "Do not materialize archive symlinks unless their final resolved target is boundary-checked.",
				Evidence: model.Evidence{Location: displayPath, Details: map[string]string{"entry": truncate(normalized, 200)}},
			})
		}
		ratio := compressionRatio(entry)
		if entry.UncompressedSize64 > uint64(limits.MaxArchiveEntryBytes) || stats.UncompressedBytes > uint64(limits.MaxArchiveTotalBytes) || ratio > limits.MaxCompressionRatio {
			stats.SuspiciousRatios++
			stats.LimitHit = true
			report.Findings = append(report.Findings, model.Finding{
				RuleID: "archive.decompression-bomb-risk", Module: "archive-security", Title: "Archive expansion exceeds safe limits", Severity: model.SeverityHigh, Confidence: "high", CWE: "CWE-409",
				Description: "An entry or the cumulative archive size/ratio exceeds configured decompression limits.", Remediation: "Reject or inspect the artifact in a resource-capped sandbox with strict entry and total expansion limits.",
				Evidence: model.Evidence{Location: displayPath, Details: map[string]string{"entry": truncate(normalized, 200), "uncompressed_bytes": fmt.Sprintf("%d", entry.UncompressedSize64), "compression_ratio": fmt.Sprintf("%.1f", ratio)}},
			})
			continue
		}
		if visitor != nil && entry.Flags&0x1 == 0 && !entry.FileInfo().IsDir() {
			if err := visitor(entry, normalized); err != nil {
				stats.LimitHit = true
			}
		}
	}
	return stats, nil
}

func safeArchiveName(name string) (string, bool) {
	if name == "" || strings.ContainsRune(name, '\x00') {
		return "", false
	}
	forward := strings.ReplaceAll(name, "\\", "/")
	driveQualified := len(forward) >= 2 && forward[1] == ':' && ((forward[0] >= 'a' && forward[0] <= 'z') || (forward[0] >= 'A' && forward[0] <= 'Z'))
	if strings.HasPrefix(forward, "/") || filepath.VolumeName(name) != "" || driveQualified {
		return "", false
	}
	clean := path.Clean(forward)
	if clean == ".." || strings.HasPrefix(clean, "../") {
		return "", false
	}
	return strings.TrimPrefix(clean, "./"), true
}

func compressionRatio(entry *zip.File) float64 {
	if entry.UncompressedSize64 == 0 {
		return 0
	}
	if entry.CompressedSize64 == 0 {
		return float64(entry.UncompressedSize64)
	}
	return float64(entry.UncompressedSize64) / float64(entry.CompressedSize64)
}

func readArchiveEntry(entry *zip.File, limit int64) ([]byte, bool, error) {
	if entry.UncompressedSize64 > uint64(limit) {
		return nil, true, nil
	}
	reader, err := entry.Open()
	if err != nil {
		return nil, false, err
	}
	defer reader.Close()
	data, err := io.ReadAll(io.LimitReader(reader, limit+1))
	if err != nil {
		return nil, false, err
	}
	if int64(len(data)) > limit {
		return data[:limit], true, nil
	}
	return data, false, nil
}
