package scan

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

func inspectTargetMetadata(tree *targetTree, hashLimit int64) (map[string]string, bool, error) {
	if tree == nil || tree.TargetInfo == nil {
		return nil, false, fmt.Errorf("bounded target metadata is unavailable")
	}
	info := tree.TargetInfo
	metadata := map[string]string{
		"size_bytes": fmt.Sprintf("%d", info.Size()),
	}
	if info.IsDir() {
		metadata["file_type"] = "directory"
		return metadata, false, nil
	}
	if !info.Mode().IsRegular() || len(tree.Files) != 1 {
		return nil, false, fmt.Errorf("target is not a regular file or directory")
	}
	record := tree.Files[0]
	f, openedInfo, err := openRecord(record)
	if err != nil {
		return nil, false, err
	}
	defer f.Close()
	info = openedInfo
	metadata["size_bytes"] = fmt.Sprintf("%d", info.Size())
	head := make([]byte, 512)
	n, readErr := io.ReadFull(f, head)
	if readErr != nil && readErr != io.ErrUnexpectedEOF {
		return nil, false, readErr
	}
	head = head[:n]
	tail := make([]byte, 512)
	if info.Size() > 0 {
		offset := info.Size() - int64(len(tail))
		if offset < 0 {
			offset = 0
		}
		n, _ = f.ReadAt(tail, offset)
		tail = tail[:n]
	}
	metadata["file_type"] = detectFileType(filepath.Ext(record.Relative), head, tail)
	if info.Size() > hashLimit {
		metadata["sha256_status"] = "not-computed-size-limit"
		return metadata, true, nil
	}
	digest, bytesHashed, stable, err := hashStableFile(f, info, hashLimit)
	if err != nil {
		return nil, false, err
	}
	metadata["bytes_hashed"] = fmt.Sprintf("%d", bytesHashed)
	if !stable {
		metadata["sha256_status"] = "not-computed-file-changed"
		return metadata, true, nil
	}
	metadata["sha256"] = digest
	metadata["sha256_status"] = "complete"
	metadata["hash_scope"] = "full-file-stable-read"
	return metadata, false, nil
}

func hashStableFile(f interface {
	io.Reader
	io.Seeker
	Stat() (fs.FileInfo, error)
}, initial fs.FileInfo, hashLimit int64) (digest string, bytesHashed int64, stable bool, err error) {
	if initial.Size() > hashLimit {
		return "", 0, false, nil
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return "", 0, false, err
	}
	hash := sha256.New()
	bytesHashed, err = io.CopyN(hash, f, initial.Size())
	if err != nil {
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			return "", bytesHashed, false, nil
		}
		return "", bytesHashed, false, err
	}
	var extra [1]byte
	extraBytes, readErr := f.Read(extra[:])
	if readErr != nil && readErr != io.EOF {
		return "", bytesHashed, false, readErr
	}
	after, statErr := f.Stat()
	if statErr != nil {
		return "", bytesHashed, false, statErr
	}
	if extraBytes != 0 || after.Size() != initial.Size() || !after.ModTime().Equal(initial.ModTime()) || !os.SameFile(initial, after) {
		return "", bytesHashed, false, nil
	}
	return hex.EncodeToString(hash.Sum(nil)), bytesHashed, true, nil
}

// invalidatePublishedTargetHashIfChanged performs a second bounded stable read
// after analysis. A mobile or desktop artifact can otherwise be modified after
// metadata collection, leaving the report's SHA-256 unrelated to the bytes
// inspected by later modules.
func invalidatePublishedTargetHashIfChanged(tree *targetTree, metadata map[string]string, hashLimit int64) bool {
	expected := metadata["sha256"]
	if expected == "" || tree == nil || tree.TargetIsDir || len(tree.Files) != 1 {
		return false
	}
	f, info, err := openRecord(tree.Files[0])
	if err == nil {
		defer f.Close()
		digest, _, stable, hashErr := hashStableFile(f, info, hashLimit)
		if hashErr == nil && stable && digest == expected {
			return false
		}
	}
	delete(metadata, "sha256")
	delete(metadata, "bytes_hashed")
	delete(metadata, "hash_scope")
	metadata["sha256_status"] = "invalidated-file-changed-during-scan"
	metadata["stability_status"] = "changed-or-unverifiable-during-scan"
	return true
}

func detectFileType(extension string, head, tail []byte) string {
	extension = strings.ToLower(extension)
	switch {
	case len(head) >= 4 && bytes.Equal(head[:4], []byte{0x7f, 'E', 'L', 'F'}):
		return "ELF executable or shared object"
	case len(head) >= 2 && bytes.Equal(head[:2], []byte{'M', 'Z'}):
		return "Windows PE executable"
	case len(head) >= 4 && isMachOMagic(head[:4]):
		return "Mach-O executable"
	case len(head) >= 4 && (bytes.Equal(head[:4], []byte{'P', 'K', 0x03, 0x04}) || bytes.Equal(head[:4], []byte{'P', 'K', 0x05, 0x06}) || bytes.Equal(head[:4], []byte{'P', 'K', 0x07, 0x08})):
		if extension == ".apk" {
			return "Android APK (ZIP container)"
		}
		if extension == ".ipa" {
			return "Apple IPA (ZIP container)"
		}
		return "ZIP container"
	case len(head) >= 4 && bytes.Equal(head[:4], []byte("dex\n")):
		return "Android DEX bytecode"
	case len(head) >= 8 && bytes.Equal(head[:8], []byte{0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1}):
		return "OLE compound document or MSI"
	case len(tail) >= 512 && bytes.Equal(tail[len(tail)-512:len(tail)-508], []byte("koly")):
		return "Apple DMG (UDIF)"
	case extension == ".asar":
		return "Electron ASAR archive"
	case extension == ".aab":
		return "Android App Bundle"
	case extension == ".app":
		return "macOS application bundle"
	default:
		return "unknown or data file"
	}
}

func isMachOMagic(value []byte) bool {
	magics := [][]byte{
		{0xfe, 0xed, 0xfa, 0xce}, {0xce, 0xfa, 0xed, 0xfe},
		{0xfe, 0xed, 0xfa, 0xcf}, {0xcf, 0xfa, 0xed, 0xfe},
		{0xca, 0xfe, 0xba, 0xbe}, {0xbe, 0xba, 0xfe, 0xca},
	}
	for _, magic := range magics {
		if bytes.Equal(value, magic) {
			return true
		}
	}
	return false
}
