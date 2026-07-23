package scan

import (
	"archive/zip"
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"sort"
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

type archiveLimitError struct {
	kind    string
	current uint64
	limit   uint64
}

func (e *archiveLimitError) Error() string {
	return fmt.Sprintf("%s limit exceeded (%d > %d)", e.kind, e.current, e.limit)
}

func inspectZIP(record fileRecord, displayPath string, limits Limits, report *model.Report, visitor archiveVisitor) (archiveStats, error) {
	var stats archiveStats
	f, info, err := openRecord(record)
	if err != nil {
		return stats, fmt.Errorf("open ZIP archive safely: %w", err)
	}
	defer f.Close()
	actualEntries, err := preflightZIP(f, info.Size(), limits.MaxArchiveTotalBytes, limits.MaxArchiveEntries)
	if err != nil {
		var limitErr *archiveLimitError
		if !errors.As(err, &limitErr) {
			return stats, fmt.Errorf("ZIP preflight parse failed: %w", err)
		}
		stats.LimitHit = true
		rule, title := "archive.container-limit", "Archive container exceeds safe resource limits"
		if limitErr.kind == "entries" {
			rule, title = "archive.entry-limit", "Archive contains too many central-directory entries"
		}
		appendFinding(report, model.Finding{
			RuleID: rule, Module: "archive-security", Title: title, Severity: model.SeverityHigh, Confidence: "high", CWE: "CWE-409",
			Description: "A verified ZIP size or entry count exceeds the configured safe parsing limit.", Remediation: "Reject the artifact or inspect it in a memory- and CPU-capped isolated worker.",
			Evidence: model.Evidence{Location: displayPath, Details: map[string]string{"limit_kind": limitErr.kind, "observed": fmt.Sprintf("%d", limitErr.current), "limit": fmt.Sprintf("%d", limitErr.limit)}},
		})
		return stats, nil
	}
	reader, err := zip.NewReader(f, info.Size())
	if err != nil {
		return stats, fmt.Errorf("open ZIP archive: %w", err)
	}
	if len(reader.File) != actualEntries {
		return stats, fmt.Errorf("ZIP parser entry count differs from bounded preflight")
	}
	seen := make(map[string]struct{})
	symlinkTargets := make(map[string]string)
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
		isSymlink := entry.Mode()&os.ModeSymlink != 0
		if isSymlink {
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
		if isSymlink && entry.Flags&0x1 == 0 {
			target, truncated, targetErr := readArchiveEntry(entry, 4_096)
			if targetErr != nil || truncated {
				stats.LimitHit = true
			} else if _, exists := symlinkTargets[normalized]; !exists {
				symlinkTargets[normalized] = string(target)
			}
		}
		if visitor != nil && entry.Flags&0x1 == 0 && !entry.FileInfo().IsDir() && !isSymlink {
			if err := visitor(entry, normalized); err != nil {
				stats.LimitHit = true
			}
		}
	}
	reportArchiveSymlinkRisks(displayPath, symlinkTargets, report)
	return stats, nil
}

func preflightZIP(f *os.File, size, inputLimit int64, maxEntries int) (int, error) {
	if size > inputLimit {
		return 0, &archiveLimitError{kind: "compressed-input-bytes", current: uint64(size), limit: uint64(inputLimit)}
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
	position := findZIPendRecord(tail)
	if position < 0 {
		return 0, fmt.Errorf("ZIP end record is missing")
	}
	diskNumber := binary.LittleEndian.Uint16(tail[position+4 : position+6])
	centralDisk := binary.LittleEndian.Uint16(tail[position+6 : position+8])
	entriesOnDisk := binary.LittleEndian.Uint16(tail[position+8 : position+10])
	totalEntries := binary.LittleEndian.Uint16(tail[position+10 : position+12])
	centralSize := binary.LittleEndian.Uint32(tail[position+12 : position+16])
	centralOffset := binary.LittleEndian.Uint32(tail[position+16 : position+20])
	if entriesOnDisk == 0xffff || totalEntries == 0xffff || centralSize == 0xffffffff || centralOffset == 0xffffffff {
		return 0, fmt.Errorf("ZIP64 central directory requires isolated parsing")
	}
	if diskNumber != 0 || centralDisk != 0 || entriesOnDisk != totalEntries {
		return 0, fmt.Errorf("multi-disk ZIP is unsupported")
	}
	centralLimit := int64(16 << 20)
	if inputLimit < centralLimit {
		centralLimit = inputLimit
	}
	if int64(centralSize) > centralLimit {
		return 0, &archiveLimitError{kind: "central-directory-bytes", current: uint64(centralSize), limit: uint64(centralLimit)}
	}
	eocdOffset := size - readSize + int64(position)
	if int64(centralSize) > eocdOffset {
		return 0, fmt.Errorf("central directory offset is invalid")
	}
	centralStart := eocdOffset - int64(centralSize)
	baseOffset := centralStart - int64(centralOffset)
	if baseOffset < 0 {
		return 0, fmt.Errorf("central directory base offset is invalid")
	}
	actualEntries, err := countCentralDirectoryEntries(f, centralStart, eocdOffset, maxEntries)
	if err != nil {
		return 0, err
	}
	if actualEntries != int(totalEntries) {
		return 0, fmt.Errorf("central directory count does not match the end record")
	}
	return actualEntries, nil
}

func findZIPendRecord(tail []byte) int {
	signature := []byte{'P', 'K', 0x05, 0x06}
	for position := len(tail) - 22; position >= 0; position-- {
		if !bytes.Equal(tail[position:position+4], signature) {
			continue
		}
		commentLength := int(binary.LittleEndian.Uint16(tail[position+20 : position+22]))
		if position+22+commentLength == len(tail) {
			return position
		}
	}
	return -1
}

func countCentralDirectoryEntries(f *os.File, start, end int64, maxEntries int) (int, error) {
	count := 0
	for offset := start; offset < end; {
		remaining := end - offset
		if remaining < 4 {
			return 0, fmt.Errorf("truncated central directory record")
		}
		var signature [4]byte
		if _, err := f.ReadAt(signature[:], offset); err != nil {
			return 0, fmt.Errorf("read central directory signature: %w", err)
		}
		switch string(signature[:]) {
		case "PK\x01\x02":
			if remaining < 46 {
				return 0, fmt.Errorf("truncated central file header")
			}
			var header [46]byte
			if _, err := f.ReadAt(header[:], offset); err != nil {
				return 0, fmt.Errorf("read central file header: %w", err)
			}
			recordSize := int64(46) + int64(binary.LittleEndian.Uint16(header[28:30])) + int64(binary.LittleEndian.Uint16(header[30:32])) + int64(binary.LittleEndian.Uint16(header[32:34]))
			if recordSize > remaining {
				return 0, fmt.Errorf("central file header exceeds directory bounds")
			}
			count++
			if count > maxEntries {
				return 0, &archiveLimitError{kind: "entries", current: uint64(count), limit: uint64(maxEntries)}
			}
			offset += recordSize
		case "PK\x05\x05":
			if remaining < 6 {
				return 0, fmt.Errorf("truncated central digital signature")
			}
			var header [6]byte
			if _, err := f.ReadAt(header[:], offset); err != nil {
				return 0, fmt.Errorf("read central digital signature: %w", err)
			}
			recordSize := int64(6) + int64(binary.LittleEndian.Uint16(header[4:6]))
			if recordSize > remaining {
				return 0, fmt.Errorf("central digital signature exceeds directory bounds")
			}
			offset += recordSize
		default:
			return 0, fmt.Errorf("unknown central directory record")
		}
	}
	return count, nil
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

func reportArchiveSymlinkRisks(displayPath string, links map[string]string, report *model.Report) {
	names := make([]string, 0, len(links))
	for name := range links {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		escapes, cycle := archiveSymlinkResolution(name, links)
		if escapes {
			appendFinding(report, model.Finding{
				RuleID: "archive.symlink-traversal", Module: "archive-security", Title: "Archive symlink resolves outside the extraction root", Severity: model.SeverityHigh, Confidence: "high", CWE: "CWE-22",
				Description: "Static correlation of archive symlink targets, including chained links and path prefixes, reaches outside the virtual extraction root.", Remediation: "Reject the archive and never materialize links without resolving the complete chain inside a descriptor-bounded extraction root.",
				Evidence: model.Evidence{Location: displayPath, Details: map[string]string{"entry": truncate(name, 200), "resolution": "outside-archive-root"}},
			})
		} else if cycle {
			appendFinding(report, model.Finding{
				RuleID: "archive.symlink-cycle", Module: "archive-security", Title: "Archive contains a cyclic symlink chain", Severity: model.SeverityMedium, Confidence: "high", CWE: "CWE-835",
				Description: "Static correlation found a symlink cycle that can cause extractor loops or parser inconsistencies.", Remediation: "Reject cyclic archive links and cap link resolution depth.",
				Evidence: model.Evidence{Location: displayPath, Details: map[string]string{"entry": truncate(name, 200)}},
			})
		}
	}
}

func archiveSymlinkResolution(start string, links map[string]string) (escapes bool, cycle bool) {
	candidate, safe := resolveArchiveLinkTarget(start, links[start], "")
	if !safe {
		return true, false
	}
	visited := map[string]struct{}{start: {}}
	for depth := 0; depth < 64; depth++ {
		linkName, suffix, found := archiveLinkPrefix(candidate, links)
		if !found {
			return false, false
		}
		if _, exists := visited[linkName]; exists {
			return false, true
		}
		visited[linkName] = struct{}{}
		candidate, safe = resolveArchiveLinkTarget(linkName, links[linkName], suffix)
		if !safe {
			return true, false
		}
	}
	return false, true
}

func resolveArchiveLinkTarget(linkName, target, suffix string) (string, bool) {
	if target == "" || strings.ContainsRune(target, '\x00') {
		return "", false
	}
	forward := strings.ReplaceAll(target, "\\", "/")
	driveQualified := len(forward) >= 2 && forward[1] == ':' && ((forward[0] >= 'a' && forward[0] <= 'z') || (forward[0] >= 'A' && forward[0] <= 'Z'))
	if strings.HasPrefix(forward, "/") || driveQualified {
		return "", false
	}
	resolved := path.Clean(path.Join(path.Dir(linkName), forward))
	if suffix != "" {
		resolved = path.Clean(path.Join(resolved, suffix))
	}
	if resolved == ".." || strings.HasPrefix(resolved, "../") || strings.HasPrefix(resolved, "/") {
		return "", false
	}
	return strings.TrimPrefix(resolved, "./"), true
}

func archiveLinkPrefix(candidate string, links map[string]string) (linkName, suffix string, found bool) {
	parts := strings.Split(candidate, "/")
	for length := len(parts); length > 0; length-- {
		prefix := strings.Join(parts[:length], "/")
		if _, exists := links[prefix]; !exists {
			continue
		}
		return prefix, strings.Join(parts[length:], "/"), true
	}
	return "", "", false
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
