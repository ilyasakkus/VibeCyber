package scan

import (
	"archive/zip"
	"bytes"
	"encoding/binary"
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
	f, info, err := openRegularNoFollow(filename)
	if err != nil {
		return stats, fmt.Errorf("open ZIP archive safely: %w", err)
	}
	defer f.Close()
	declaredEntries, err := preflightZIP(f, info.Size(), limits.MaxArchiveTotalBytes)
	if err != nil {
		stats.LimitHit = true
		appendFinding(report, model.Finding{
			RuleID: "archive.container-limit", Module: "archive-security", Title: "Archive container exceeds safe parsing limits", Severity: model.SeverityHigh, Confidence: "high", CWE: "CWE-409",
			Description: "The ZIP input size, directory layout, or ZIP64 metadata exceeds the dependency-free parser's safe preflight limits.", Remediation: "Inspect the artifact only in a memory- and CPU-capped isolated worker.",
			Evidence: model.Evidence{Location: displayPath, Details: map[string]string{"reason": truncate(err.Error(), 200)}},
		})
		return stats, nil
	}
	if declaredEntries > limits.MaxArchiveEntries {
		stats.LimitHit = true
		appendFinding(report, model.Finding{
			RuleID: "archive.entry-limit", Module: "archive-security", Title: "Archive declares too many entries", Severity: model.SeverityHigh, Confidence: "high", CWE: "CWE-409",
			Description: "The central directory declares more entries than the configured safe inspection limit.", Remediation: "Reject the artifact or inspect it in an isolated worker with strict entry and memory limits.",
			Evidence: model.Evidence{Location: displayPath, Details: map[string]string{"declared_entries": fmt.Sprintf("%d", declaredEntries)}},
		})
		return stats, nil
	}
	reader, err := zip.NewReader(f, info.Size())
	if err != nil {
		return stats, fmt.Errorf("open ZIP archive: %w", err)
	}
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
			appendFinding(report, model.Finding{
				RuleID: "archive.path-traversal", Module: "archive-security", Title: "Archive entry can escape the extraction directory", Severity: model.SeverityHigh, Confidence: "high", CWE: "CWE-22",
				Description: "A ZIP entry uses an absolute path, parent traversal, or drive-qualified name.", Remediation: "Reject the archive or normalize and boundary-check every destination before extraction.",
				Evidence: model.Evidence{Location: displayPath, Details: map[string]string{"entry": truncate(entry.Name, 200)}},
			})
			continue
		}
		if _, duplicate := seen[normalized]; duplicate {
			appendFinding(report, model.Finding{
				RuleID: "archive.duplicate-entry", Module: "archive-security", Title: "Archive contains duplicate normalized paths", Severity: model.SeverityMedium, Confidence: "high", CWE: "CWE-436",
				Description: "More than one ZIP record maps to the same normalized path, which can produce parser-dependent results.", Remediation: "Reject archives with duplicate normalized entry names.",
				Evidence: model.Evidence{Location: displayPath, Details: map[string]string{"entry": truncate(normalized, 200)}},
			})
		} else {
			seen[normalized] = struct{}{}
		}
		if entry.Flags&0x1 != 0 {
			stats.Encrypted++
			appendFinding(report, model.Finding{
				RuleID: "archive.encrypted-entry", Module: "archive-security", Title: "Encrypted archive entry was not inspected", Severity: model.SeverityInfo, Confidence: "high",
				Description: "The ZIP entry is encrypted, so its content cannot be statically inspected by the built-in scanner.", Remediation: "Provide an authorized, decrypted artifact in an isolated workspace for complete inspection.",
				Evidence: model.Evidence{Location: displayPath, Details: map[string]string{"entry": truncate(normalized, 200)}},
			})
		}
		if entry.Mode()&os.ModeSymlink != 0 {
			stats.Symlinks++
			appendFinding(report, model.Finding{
				RuleID: "archive.symbolic-link", Module: "archive-security", Title: "Archive contains a symbolic link", Severity: model.SeverityLow, Confidence: "high", CWE: "CWE-59",
				Description: "Unsafe extractors may follow a symlink in the archive and write outside the intended destination.", Remediation: "Do not materialize archive symlinks unless their final resolved target is boundary-checked.",
				Evidence: model.Evidence{Location: displayPath, Details: map[string]string{"entry": truncate(normalized, 200)}},
			})
		}
		ratio := compressionRatio(entry)
		ratioRisk := ratio > limits.MaxCompressionRatio && entry.UncompressedSize64 > 1<<20
		if entry.UncompressedSize64 > uint64(limits.MaxArchiveEntryBytes) || stats.UncompressedBytes > uint64(limits.MaxArchiveTotalBytes) || ratioRisk {
			stats.SuspiciousRatios++
			stats.LimitHit = true
			appendFinding(report, model.Finding{
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

func preflightZIP(f *os.File, size, inputLimit int64) (int, error) {
	if size > inputLimit {
		return 0, fmt.Errorf("compressed input exceeds %d bytes", inputLimit)
	}
	const maxEOCDSearch = int64(65_557) // 22-byte EOCD plus maximum ZIP comment.
	readSize := size
	if readSize > maxEOCDSearch {
		readSize = maxEOCDSearch
	}
	if readSize < 22 {
		return 0, fmt.Errorf("ZIP end record is missing")
	}
	tail := make([]byte, readSize)
	if _, err := f.ReadAt(tail, size-readSize); err != nil && err != io.EOF {
		return 0, fmt.Errorf("read ZIP end record: %w", err)
	}
	signature := []byte{'P', 'K', 0x05, 0x06}
	position := bytes.LastIndex(tail, signature)
	if position < 0 || position+22 > len(tail) {
		return 0, fmt.Errorf("ZIP end record is missing")
	}
	commentLength := int(binary.LittleEndian.Uint16(tail[position+20 : position+22]))
	if position+22+commentLength != len(tail) {
		return 0, fmt.Errorf("ZIP end record has trailing or inconsistent data")
	}
	entriesOnDisk := binary.LittleEndian.Uint16(tail[position+8 : position+10])
	totalEntries := binary.LittleEndian.Uint16(tail[position+10 : position+12])
	centralSize := binary.LittleEndian.Uint32(tail[position+12 : position+16])
	if entriesOnDisk == 0xffff || totalEntries == 0xffff || centralSize == 0xffffffff {
		return 0, fmt.Errorf("ZIP64 central directory requires isolated parsing")
	}
	if entriesOnDisk != totalEntries {
		return 0, fmt.Errorf("multi-disk ZIP is unsupported")
	}
	centralLimit := int64(16 << 20)
	if inputLimit < centralLimit {
		centralLimit = inputLimit
	}
	if int64(centralSize) > centralLimit {
		return 0, fmt.Errorf("central directory exceeds %d bytes", centralLimit)
	}
	return int(totalEntries), nil
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
