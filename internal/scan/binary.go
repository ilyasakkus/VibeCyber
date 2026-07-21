package scan

import (
	"encoding/binary"
	"fmt"
	"io"
	"os"

	"github.com/webcyber/webcyber/internal/model"
)

const (
	peDynamicBase               = 0x0040
	peNXCompat                  = 0x0100
	peGuardCF                   = 0x4000
	elfPTGNUStack               = 0x6474e551
	elfPTGNURelro               = 0x6474e552
	elfPFX                      = 0x1
	machFlagAllowStackExecution = 0x00020000
	machFlagPIE                 = 0x00200000
)

// inspectBinaryProtection parses only bounded executable headers. It never
// loads or executes the artifact and avoids general-purpose binary parsers.
func inspectBinaryProtection(record fileRecord, report *model.Report) (recognized bool, complete bool, format string) {
	f, err := os.Open(record.Absolute)
	if err != nil {
		return false, false, ""
	}
	defer f.Close()
	head := make([]byte, 64)
	n, err := io.ReadFull(f, head)
	if err != nil && err != io.ErrUnexpectedEOF {
		return false, false, ""
	}
	head = head[:n]
	if len(head) >= 2 && head[0] == 'M' && head[1] == 'Z' {
		return true, inspectPEHeader(f, record, report, head), "PE"
	}
	if len(head) >= 4 && head[0] == 0x7f && head[1] == 'E' && head[2] == 'L' && head[3] == 'F' {
		return true, inspectELFHeader(f, record, report, head), "ELF"
	}
	if len(head) >= 4 && isMachOMagic(head[:4]) {
		return true, inspectMachOHeader(record, report, head), "Mach-O"
	}
	return false, false, ""
}

func inspectPEHeader(f *os.File, record fileRecord, report *model.Report, head []byte) bool {
	if len(head) < 64 {
		return false
	}
	offset := int64(binary.LittleEndian.Uint32(head[0x3c:0x40]))
	if offset < 64 || offset > record.Info.Size()-26 || offset > 16<<20 {
		return false
	}
	buffer := make([]byte, 96)
	n, err := f.ReadAt(buffer, offset)
	if err != nil && err != io.EOF {
		return false
	}
	buffer = buffer[:n]
	if len(buffer) < 26 || string(buffer[:4]) != "PE\x00\x00" {
		return false
	}
	optionalSize := int(binary.LittleEndian.Uint16(buffer[20:22]))
	if optionalSize < 72 || optionalSize > 4096 {
		return false
	}
	optional := make([]byte, optionalSize)
	n, err = f.ReadAt(optional, offset+24)
	if err != nil && err != io.EOF {
		return false
	}
	if n < 72 {
		return false
	}
	magic := binary.LittleEndian.Uint16(optional[:2])
	if magic != 0x10b && magic != 0x20b {
		return false
	}
	characteristics := binary.LittleEndian.Uint16(optional[70:72])
	checks := []struct {
		mask        uint16
		rule, title string
		severity    model.Severity
		remediation string
	}{
		{peDynamicBase, "desktop.pe.aslr-missing", "PE image is not marked for ASLR", model.SeverityMedium, "Enable /DYNAMICBASE (and high-entropy VA where supported) in release builds."},
		{peNXCompat, "desktop.pe.dep-missing", "PE image is not marked DEP-compatible", model.SeverityHigh, "Enable /NXCOMPAT and remove executable writable-memory assumptions."},
		{peGuardCF, "desktop.pe.cfg-missing", "PE image is not marked for Control Flow Guard", model.SeverityLow, "Enable /guard:cf where the compiler and target platform support it."},
	}
	for _, check := range checks {
		if characteristics&check.mask == 0 {
			report.Findings = append(report.Findings, model.Finding{
				RuleID: check.rule, Module: "binary-protection", Title: check.title, Severity: check.severity, Confidence: "high", CWE: "CWE-693",
				Description: "A bounded parse of the PE optional header did not find the expected mitigation flag.", Remediation: check.remediation,
				Evidence: model.Evidence{Location: record.Relative, Details: map[string]string{"format": "PE", "dll_characteristics": fmt.Sprintf("0x%04x", characteristics)}},
			})
		}
	}
	return true
}

func inspectELFHeader(f *os.File, record fileRecord, report *model.Report, head []byte) bool {
	if len(head) < 52 || head[5] != 1 && head[5] != 2 {
		return false
	}
	var order binary.ByteOrder = binary.LittleEndian
	if head[5] == 2 {
		order = binary.BigEndian
	}
	class := head[4]
	fileType := order.Uint16(head[16:18])
	var programOffset uint64
	var entrySize, entryCount uint16
	switch class {
	case 1:
		programOffset = uint64(order.Uint32(head[28:32]))
		entrySize = order.Uint16(head[42:44])
		entryCount = order.Uint16(head[44:46])
	case 2:
		if len(head) < 64 {
			return false
		}
		programOffset = order.Uint64(head[32:40])
		entrySize = order.Uint16(head[54:56])
		entryCount = order.Uint16(head[56:58])
	default:
		return false
	}
	if entryCount > 128 || entrySize < 32 || entrySize > 256 || programOffset > uint64(record.Info.Size()) {
		return false
	}
	hasStack := false
	executableStack := false
	hasRelro := false
	entry := make([]byte, entrySize)
	for index := uint16(0); index < entryCount; index++ {
		offset := programOffset + uint64(index)*uint64(entrySize)
		if offset > uint64(record.Info.Size()) || uint64(entrySize) > uint64(record.Info.Size())-offset {
			return false
		}
		n, err := f.ReadAt(entry, int64(offset))
		if err != nil && err != io.EOF || n != len(entry) {
			return false
		}
		segmentType := order.Uint32(entry[:4])
		if segmentType == elfPTGNURelro {
			hasRelro = true
		}
		if segmentType == elfPTGNUStack {
			hasStack = true
			var flags uint32
			if class == 2 {
				flags = order.Uint32(entry[4:8])
			} else {
				flags = order.Uint32(entry[24:28])
			}
			executableStack = flags&elfPFX != 0
		}
	}
	if fileType == 2 { // ET_EXEC, rather than position-independent ET_DYN.
		appendBinaryFinding(report, record.Relative, "desktop.elf.pie-missing", "ELF executable is not position independent", model.SeverityMedium, "The ELF type is ET_EXEC, so full executable ASLR/PIE is not enabled.", "Build the executable with PIE enabled.", "ELF")
	}
	if hasStack && executableStack {
		appendBinaryFinding(report, record.Relative, "desktop.elf.executable-stack", "ELF requests an executable stack", model.SeverityHigh, "The GNU_STACK program header includes execute permission.", "Remove executable-stack requirements and rebuild with a non-executable stack.", "ELF")
	}
	if !hasRelro {
		appendBinaryFinding(report, record.Relative, "desktop.elf.relro-missing", "ELF does not declare RELRO", model.SeverityLow, "No GNU_RELRO program header was found.", "Enable full RELRO during linking where supported.", "ELF")
	}
	return true
}

func inspectMachOHeader(record fileRecord, report *model.Report, head []byte) bool {
	if len(head) < 28 {
		return false
	}
	// Universal/fat binaries need per-slice parsing, which is intentionally left
	// to the isolated deep-analysis worker.
	if (head[0] == 0xca && head[1] == 0xfe && head[2] == 0xba && head[3] == 0xbe) || (head[0] == 0xbe && head[1] == 0xba && head[2] == 0xfe && head[3] == 0xca) {
		return false
	}
	var order binary.ByteOrder = binary.BigEndian
	if head[0] == 0xce || head[0] == 0xcf {
		order = binary.LittleEndian
	}
	fileType := order.Uint32(head[12:16])
	flags := order.Uint32(head[24:28])
	if fileType == 2 && flags&machFlagPIE == 0 {
		appendBinaryFinding(report, record.Relative, "desktop.macho.pie-missing", "Mach-O executable is not marked PIE", model.SeverityMedium, "The Mach-O executable header does not contain the PIE flag.", "Build and link the application as a position-independent executable.", "Mach-O")
	}
	if flags&machFlagAllowStackExecution != 0 {
		appendBinaryFinding(report, record.Relative, "desktop.macho.executable-stack", "Mach-O permits stack execution", model.SeverityHigh, "The Mach-O header allows an executable stack.", "Remove the executable-stack linker option and remediate code that depends on it.", "Mach-O")
	}
	return true
}

func appendBinaryFinding(report *model.Report, location, rule, title string, severity model.Severity, description, remediation, format string) {
	report.Findings = append(report.Findings, model.Finding{
		RuleID: rule, Module: "binary-protection", Title: title, Severity: severity, Confidence: "high", CWE: "CWE-693",
		Description: description, Remediation: remediation, Evidence: model.Evidence{Location: location, Details: map[string]string{"format": format}},
	})
}
