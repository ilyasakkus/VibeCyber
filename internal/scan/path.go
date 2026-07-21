package scan

import (
	"bytes"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

type fileRecord struct {
	Absolute string
	Relative string
	Info     fs.FileInfo
}

type walkStats struct {
	FilesSkipped int
	Symlinks     int
	LimitHit     bool
}

var ignoredDirectories = map[string]struct{}{
	".git": {}, ".hg": {}, ".svn": {},
	"node_modules": {}, "vendor": {}, ".next": {},
	"dist": {}, "build": {}, "coverage": {},
}

func collectFiles(target string, limits Limits) (string, []fileRecord, walkStats, error) {
	var stats walkStats
	abs, err := filepath.Abs(target)
	if err != nil {
		return "", nil, stats, fmt.Errorf("resolve target: %w", err)
	}
	initial, err := os.Lstat(abs)
	if err != nil {
		return "", nil, stats, fmt.Errorf("inspect target: %w", err)
	}
	if initial.Mode()&os.ModeSymlink != 0 {
		return "", nil, stats, fmt.Errorf("target must not be a symbolic link")
	}
	realTarget, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return "", nil, stats, fmt.Errorf("resolve target links: %w", err)
	}
	realTarget, err = filepath.Abs(realTarget)
	if err != nil {
		return "", nil, stats, fmt.Errorf("normalize target: %w", err)
	}
	info, err := os.Stat(realTarget)
	if err != nil {
		return "", nil, stats, fmt.Errorf("stat target: %w", err)
	}
	if !info.IsDir() {
		if !info.Mode().IsRegular() {
			return "", nil, stats, fmt.Errorf("target is not a regular file or directory")
		}
		return filepath.Dir(realTarget), []fileRecord{{Absolute: realTarget, Relative: filepath.Base(realTarget), Info: info}}, stats, nil
	}

	root := filepath.Clean(realTarget)
	files := make([]fileRecord, 0, min(limits.MaxFiles, 256))
	err = filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			stats.FilesSkipped++
			return nil
		}
		if path == root {
			return nil
		}
		rel, relErr := filepath.Rel(root, path)
		if relErr != nil || !pathWithin(root, path) {
			stats.FilesSkipped++
			if entry.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		depth := strings.Count(filepath.Clean(rel), string(filepath.Separator)) + 1
		if depth > limits.MaxDepth {
			stats.LimitHit = true
			if entry.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if entry.Type()&os.ModeSymlink != 0 {
			stats.Symlinks++
			if entry.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if entry.IsDir() {
			if _, ignored := ignoredDirectories[entry.Name()]; ignored {
				return filepath.SkipDir
			}
			return nil
		}
		if len(files) >= limits.MaxFiles {
			stats.LimitHit = true
			return fs.SkipAll
		}
		entryInfo, infoErr := entry.Info()
		if infoErr != nil || !entryInfo.Mode().IsRegular() {
			stats.FilesSkipped++
			return nil
		}
		// Resolve every candidate and ensure that even nested links cannot escape.
		resolved, resolveErr := filepath.EvalSymlinks(path)
		if resolveErr != nil || !pathWithin(root, resolved) {
			stats.FilesSkipped++
			return nil
		}
		files = append(files, fileRecord{
			Absolute: resolved,
			Relative: filepath.ToSlash(rel),
			Info:     entryInfo,
		})
		return nil
	})
	if err != nil {
		return root, files, stats, fmt.Errorf("walk target: %w", err)
	}
	return root, files, stats, nil
}

func pathWithin(root, candidate string) bool {
	rel, err := filepath.Rel(filepath.Clean(root), filepath.Clean(candidate))
	if err != nil {
		return false
	}
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && !filepath.IsAbs(rel)
}

func readLimitedFile(record fileRecord, maxBytes int64) ([]byte, bool, error) {
	// Re-check links immediately before opening to reduce symlink race exposure.
	current, err := os.Lstat(record.Absolute)
	if err != nil {
		return nil, false, err
	}
	if current.Mode()&os.ModeSymlink != 0 || !current.Mode().IsRegular() {
		return nil, false, fmt.Errorf("file changed or is not regular")
	}
	f, err := os.Open(record.Absolute)
	if err != nil {
		return nil, false, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxBytes+1))
	if err != nil {
		return nil, false, err
	}
	if int64(len(data)) > maxBytes {
		return data[:maxBytes], true, nil
	}
	return data, false, nil
}

func isProbablyBinary(data []byte) bool {
	if len(data) == 0 {
		return false
	}
	sample := data
	if len(sample) > 8_192 {
		sample = sample[:8_192]
	}
	if bytes.IndexByte(sample, 0) >= 0 {
		return true
	}
	var controls int
	for _, b := range sample {
		if b < 0x09 || (b > 0x0d && b < 0x20) {
			controls++
		}
	}
	return controls*100/len(sample) > 10
}
