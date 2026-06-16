package heuristics

import (
	"debug/pe"
	"os"
	"strings"
)

// suspiciousImports are API calls commonly used by shellcode loaders / injectors.
var suspiciousImports = []string{
	"VirtualAllocEx",
	"WriteProcessMemory",
	"CreateRemoteThread",
	"NtWriteVirtualMemory",
	"RtlCreateUserThread",
	"SetWindowsHookEx",
	"QueueUserAPC",
	"ZwCreateThreadEx",
}

// AnalyzePE heuristically scores a Windows PE file (0–100).
// ≥70 → suspicious; ≥85 → highly suspicious (likely packed / injector).
func AnalyzePE(path string, entropyWarn float64) (score int, reasons []string) {
	f, err := os.Open(path)
	if err != nil {
		return 0, nil
	}
	defer f.Close()

	pf, err := pe.NewFile(f)
	if err != nil {
		return 0, nil // not a valid PE
	}
	defer pf.Close()

	// Check section entropy
	for _, sec := range pf.Sections {
		data, err := sec.Data()
		if err != nil || len(data) == 0 {
			continue
		}
		e := SectionEntropy(data)
		if e >= entropyWarn {
			score += 30
			reasons = append(reasons,
				strings.TrimRight(sec.Name, "\x00")+
					" section entropy high (packed/encrypted)")
			break // count once
		}
	}

	// Check imports for loader/injector patterns
	impTab, _ := pf.ImportedSymbols()
	for _, sym := range impTab {
		// sym is "DLL.FunctionName"
		parts := strings.SplitN(sym, ".", 2)
		fn := parts[len(parts)-1]
		for _, sus := range suspiciousImports {
			if strings.EqualFold(fn, sus) {
				score += 25
				reasons = append(reasons, "suspicious import: "+fn)
				break
			}
		}
	}

	// Check for very few sections (unusual for legit binaries)
	if len(pf.Sections) < 2 {
		score += 10
		reasons = append(reasons, "abnormally few PE sections")
	}

	// Check for missing standard section names (text/data/rdata)
	hasText := false
	for _, sec := range pf.Sections {
		if strings.Contains(strings.ToLower(strings.TrimRight(sec.Name, "\x00")), "text") {
			hasText = true
		}
	}
	if !hasText && len(pf.Sections) > 0 {
		score += 15
		reasons = append(reasons, "no .text section (obfuscated PE)")
	}

	if score > 100 {
		score = 100
	}
	return score, reasons
}
