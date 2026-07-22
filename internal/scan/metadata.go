package scan

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

func inspectTargetMetadata(target string, hashLimit int64) (map[string]string, bool, error) {
	info, err := os.Lstat(target)
	if err != nil {
		return nil, false, err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, false, fmt.Errorf("target must not be a symbolic link")
	}
	metadata := map[string]string{
		"size_bytes": fmt.Sprintf("%d", info.Size()),
	}
	if info.IsDir() {
		metadata["file_type"] = "directory"
		return metadata, false, nil
	}
	if !info.Mode().IsRegular() {
		return nil, false, fmt.Errorf("target is not a regular file or directory")
	}
	f, openedInfo, err := openRegularNoFollow(target)
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
	metadata["file_type"] = detectFileType(filepath.Ext(target), head, tail)
	if info.Size() > hashLimit {
		metadata["sha256"] = "not-computed-size-limit"
		return metadata, true, nil
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return nil, false, err
	}
	hash := sha256.New()
	if _, err := io.Copy(hash, io.LimitReader(f, hashLimit+1)); err != nil {
		return nil, false, err
	}
	metadata["sha256"] = hex.EncodeToString(hash.Sum(nil))
	return metadata, false, nil
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
