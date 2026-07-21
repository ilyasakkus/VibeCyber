package scan

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"

	"github.com/webcyber/webcyber/internal/model"
)

func TestBoundedPEHeaderFindsMissingMitigations(t *testing.T) {
	filename := filepath.Join(t.TempDir(), "sample.exe")
	data := make([]byte, 64+24+96)
	copy(data, []byte("MZ"))
	binary.LittleEndian.PutUint32(data[0x3c:0x40], 64)
	copy(data[64:], []byte("PE\x00\x00"))
	binary.LittleEndian.PutUint16(data[64+20:64+22], 96)
	binary.LittleEndian.PutUint16(data[64+24:64+26], 0x20b)
	// DllCharacteristics at optional header offset 70 intentionally remains 0.
	if err := os.WriteFile(filename, data, 0o600); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filename)
	if err != nil {
		t.Fatal(err)
	}
	report := model.Report{}
	recognized, complete, format := inspectBinaryProtection(fileRecord{Absolute: filename, Relative: "sample.exe", Info: info}, &report)
	if !recognized || !complete || format != "PE" {
		t.Fatalf("recognized=%v complete=%v format=%q", recognized, complete, format)
	}
	if len(report.Findings) != 3 {
		t.Fatalf("findings=%d, want 3", len(report.Findings))
	}
}
