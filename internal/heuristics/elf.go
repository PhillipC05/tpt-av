package heuristics

import (
	"debug/elf"
	"os"
	"strings"
)

// unusualELFSections are section names sometimes found in malicious ELF binaries.
var unusualELFSections = []string{
	".evil", ".hack", ".stage2", ".payload",
}

// AnalyzeELF heuristically scores a Linux/Unix ELF binary (0–100).
func AnalyzeELF(path string, entropyWarn float64) (score int, reasons []string) {
	f, err := os.Open(path)
	if err != nil {
		return 0, nil
	}
	defer f.Close()

	ef, err := elf.NewFile(f)
	if err != nil {
		return 0, nil // not a valid ELF
	}
	defer ef.Close()

	// Check section entropy
	for _, sec := range ef.Sections {
		if sec.Size == 0 || sec.Type == elf.SHT_NOBITS {
			continue
		}
		data, err := sec.Data()
		if err != nil || len(data) == 0 {
			continue
		}
		e := SectionEntropy(data)
		if e >= entropyWarn {
			score += 30
			reasons = append(reasons, sec.Name+" section entropy high (packed/encrypted)")
			break
		}
	}

	// Check for known suspicious section names
	for _, sec := range ef.Sections {
		for _, bad := range unusualELFSections {
			if strings.EqualFold(sec.Name, bad) {
				score += 40
				reasons = append(reasons, "suspicious section name: "+sec.Name)
			}
		}
	}

	// SUID/SGID binaries in non-system paths are suspicious
	fi, err := f.Stat()
	if err == nil {
		mode := fi.Mode()
		if mode&os.ModeSetuid != 0 || mode&os.ModeSetgid != 0 {
			if !strings.HasPrefix(path, "/usr/") && !strings.HasPrefix(path, "/bin/") {
				score += 25
				reasons = append(reasons, "SUID/SGID bit set outside system directory")
			}
		}
	}

	// Very small ELF with high entropy is suspicious (shellcode loader)
	fi2, err2 := os.Stat(path)
	if err2 == nil && fi2.Size() < 4096 && score >= 30 {
		score += 10
		reasons = append(reasons, "very small binary with high entropy")
	}

	if score > 100 {
		score = 100
	}
	return score, reasons
}

// AnalyzeFile dispatches to PE or ELF analyzer based on file magic bytes.
// Returns (score, reasons, analyzed) where analyzed=false means the file
// is not a recognized executable format.
func AnalyzeFile(path string, entropyWarn float64, scoreWarn, scoreCritical int) (score int, reasons []string, severity string) {
	// Read first 4 bytes for magic
	f, err := os.Open(path)
	if err != nil {
		return 0, nil, ""
	}
	magic := make([]byte, 4)
	n, _ := f.Read(magic)
	f.Close()
	if n < 2 {
		return 0, nil, ""
	}

	switch {
	case magic[0] == 0x4D && magic[1] == 0x5A: // MZ → PE
		score, reasons = AnalyzePE(path, entropyWarn)
	case magic[0] == 0x7F && magic[1] == 'E' && magic[2] == 'L' && magic[3] == 'F': // ELF
		score, reasons = AnalyzeELF(path, entropyWarn)
	default:
		return 0, nil, ""
	}

	switch {
	case score >= scoreCritical:
		severity = "critical"
	case score >= scoreWarn:
		severity = "warn"
	}
	return score, reasons, severity
}
