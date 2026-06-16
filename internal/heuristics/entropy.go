// Package heuristics provides static file analysis using only Go stdlib.
// No external dependencies — works cross-platform without CGo.
package heuristics

import "math"

// Entropy computes the Shannon entropy (0–8) of a byte slice.
// Values above ~7.2 indicate packed, encrypted, or compressed data.
func Entropy(data []byte) float64 {
	if len(data) == 0 {
		return 0
	}
	var freq [256]float64
	for _, b := range data {
		freq[b]++
	}
	n := float64(len(data))
	var h float64
	for _, f := range freq {
		if f > 0 {
			p := f / n
			h -= p * math.Log2(p)
		}
	}
	return h
}

// SectionEntropy is a convenience alias used by pe.go and elf.go.
func SectionEntropy(section []byte) float64 {
	return Entropy(section)
}
