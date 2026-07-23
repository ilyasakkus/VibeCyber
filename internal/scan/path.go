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
	Relative string
	Info     fs.FileInfo
	root     *os.Root
}

type targetTree struct {
	RootPath    string
	Root        *os.Root
	Files       []fileRecord
	Stats       walkStats
	TargetInfo  fs.FileInfo
	TargetIsDir bool
}

func (t *targetTree) Close() error {
	if t == nil || t.Root == nil {
		return nil
	}
	return t.Root.Close()
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

func collectFiles(target string, limits Limits) (*targetTree, error) {
	var stats walkStats
	abs, err := filepath.Abs(target)
	if err != nil {
		return nil, fmt.Errorf("resolve target: %w", err)
	}
	initial, err := os.Lstat(abs)
	if err != nil {
		return nil, fmt.Errorf("inspect target: %w", err)
	}
	if initial.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("target must not be a symbolic link")
	}
	realTarget, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return nil, fmt.Errorf("resolve target links: %w", err)
	}
	realTarget, err = filepath.Abs(realTarget)
	if err != nil {
		return nil, fmt.Errorf("normalize target: %w", err)
	}
	info, err := os.Stat(realTarget)
	if err != nil {
		return nil, fmt.Errorf("stat target: %w", err)
	}
	if !os.SameFile(initial, info) {
		return nil, fmt.Errorf("target changed while its root was being established")
	}
	if !info.IsDir() && !info.Mode().IsRegular() {
		return nil, fmt.Errorf("target is not a regular file or directory")
	}

	rootPath := filepath.Clean(realTarget)
	if !info.IsDir() {
		rootPath = filepath.Dir(rootPath)
	}
	rootPathInfo, err := os.Stat(rootPath)
	if err != nil || !rootPathInfo.IsDir() {
		return nil, fmt.Errorf("stat bounded target root: %w", err)
	}
	root, err := os.OpenRoot(rootPath)
	if err != nil {
		return nil, fmt.Errorf("open bounded target root: %w", err)
	}
	openedRootInfo, err := root.Stat(".")
	if err != nil || !os.SameFile(rootPathInfo, openedRootInfo) {
		root.Close()
		return nil, fmt.Errorf("bounded target root changed while it was being opened")
	}
	tree := &targetTree{RootPath: rootPath, Root: root, TargetInfo: info, TargetIsDir: info.IsDir(), Stats: stats}
	if !info.IsDir() {
		relative := filepath.Base(realTarget)
		rootedInfo, statErr := root.Lstat(relative)
		if statErr != nil || rootedInfo.Mode()&os.ModeSymlink != 0 || !rootedInfo.Mode().IsRegular() || !os.SameFile(info, rootedInfo) {
			root.Close()
			return nil, fmt.Errorf("target file changed while its bounded root was being established")
		}
		tree.Files = []fileRecord{{Relative: filepath.ToSlash(relative), Info: rootedInfo, root: root}}
		tree.TargetInfo = rootedInfo
		return tree, nil
	}

	files := make([]fileRecord, 0, min(limits.MaxFiles, 256))
	err = fs.WalkDir(root.FS(), ".", func(relative string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			stats.FilesSkipped++
			return nil
		}
		if relative == "." {
			return nil
		}
		depth := strings.Count(relative, "/") + 1
		if depth > limits.MaxDepth {
			stats.LimitHit = true
			if entry.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if entry.Type()&os.ModeSymlink != 0 {
			stats.Symlinks++
			return nil
		}
		if entry.IsDir() {
			if _, ignored := ignoredDirectories[entry.Name()]; ignored {
				return fs.SkipDir
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
		files = append(files, fileRecord{
			Relative: filepath.ToSlash(relative),
			Info:     entryInfo,
			root:     root,
		})
		return nil
	})
	if err != nil {
		root.Close()
		return nil, fmt.Errorf("walk bounded target: %w", err)
	}
	tree.Files = files
	tree.Stats = stats
	if rootedInfo, statErr := root.Stat("."); statErr == nil {
		tree.TargetInfo = rootedInfo
	}
	return tree, nil
}

func pathWithin(root, candidate string) bool {
	rel, err := filepath.Rel(filepath.Clean(root), filepath.Clean(candidate))
	if err != nil {
		return false
	}
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && !filepath.IsAbs(rel)
}

func readLimitedFile(record fileRecord, maxBytes int64) ([]byte, bool, error) {
	f, _, err := openRecord(record)
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

// openRecord uses os.Root for component-wise boundary enforcement, then checks
// the enumerated, pre-open, and opened file identities to detect replacement.
func openRecord(record fileRecord) (*os.File, fs.FileInfo, error) {
	if record.root == nil {
		return nil, nil, fmt.Errorf("bounded root is unavailable")
	}
	name := filepath.FromSlash(record.Relative)
	before, err := record.root.Lstat(name)
	if err != nil {
		return nil, nil, err
	}
	if before.Mode()&os.ModeSymlink != 0 || !before.Mode().IsRegular() {
		return nil, nil, fmt.Errorf("file is a symbolic link or is not regular")
	}
	if record.Info == nil || !os.SameFile(record.Info, before) {
		return nil, nil, fmt.Errorf("file changed after bounded enumeration")
	}
	f, err := record.root.Open(name)
	if err != nil {
		return nil, nil, err
	}
	after, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, nil, err
	}
	if !after.Mode().IsRegular() || !os.SameFile(before, after) {
		f.Close()
		return nil, nil, fmt.Errorf("file changed while it was being opened")
	}
	return f, after, nil
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
