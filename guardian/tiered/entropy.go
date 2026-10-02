// Copyright 2025-2026 TakeInterest Inc.
// SPDX-License-Identifier: Apache-2.0

package tiered

import "math"

const (
	// DefaultEntropyThreshold is the Shannon entropy (bits/byte) above which
	// content is flagged as potentially encoded or encrypted. Base64 content
	// averages ~5.17, English prose ~4.0, typical code ~3.5-4.2.
	DefaultEntropyThreshold float64 = 4.5

	// DefaultWindowSize is the sliding window size in bytes. API keys are
	// typically 40-64 characters, so 64 captures them in a single window.
	DefaultWindowSize int = 64

	// MinWindowSize is the minimum meaningful window for Shannon entropy.
	// Below this, byte frequency distributions are too sparse to be reliable.
	MinWindowSize int = 16
)

// EntropyAnalyzer detects high-entropy strings indicating encoded or encrypted
// content such as base64-encoded API keys, encrypted payloads, or binary blobs.
type EntropyAnalyzer struct {
	Threshold  float64 // bits per byte; default 4.5
	WindowSize int     // sliding window size; default 64
}

// EntropyResult holds the analysis outcome for a single input.
type EntropyResult struct {
	MaxEntropy float64 // highest entropy found in any window
	Offset     int     // byte offset of the highest-entropy window
	Flagged    bool    // true if MaxEntropy >= Threshold
}

// NewEntropyAnalyzer returns an analyzer with default settings.
func NewEntropyAnalyzer() *EntropyAnalyzer {
	return &EntropyAnalyzer{
		Threshold:  DefaultEntropyThreshold,
		WindowSize: DefaultWindowSize,
	}
}

// WithThreshold returns a copy with a custom threshold.
func (a *EntropyAnalyzer) WithThreshold(t float64) *EntropyAnalyzer {
	return &EntropyAnalyzer{
		Threshold:  t,
		WindowSize: a.WindowSize,
	}
}

// WithWindowSize returns a copy with a custom window size (clamped to MinWindowSize).
func (a *EntropyAnalyzer) WithWindowSize(w int) *EntropyAnalyzer {
	if w < MinWindowSize {
		w = MinWindowSize
	}
	return &EntropyAnalyzer{
		Threshold:  a.Threshold,
		WindowSize: w,
	}
}

// Analyze computes Shannon entropy over sliding windows and returns the result.
// Inputs shorter than MinWindowSize return a zero-value EntropyResult.
// Uses O(1) incremental updates per window slide via precomputed entropy table.
func (a *EntropyAnalyzer) Analyze(input string) EntropyResult {
	n := len(input)
	if n < MinWindowSize {
		return EntropyResult{}
	}

	ws := a.WindowSize
	if ws > n {
		ws = n
	}

	data := []byte(input)

	// Precompute -p*log2(p) for all possible counts 0..ws.
	// table[0] = 0; table[c] = -(c/ws) * log2(c/ws) for c > 0.
	table := make([]float64, ws+1)
	total := float64(ws)
	for c := 1; c <= ws; c++ {
		p := float64(c) / total
		table[c] = -p * math.Log2(p)
	}

	// Build initial frequency table and entropy for the first window.
	var freq [256]int
	for i := 0; i < ws; i++ {
		freq[data[i]]++
	}

	var ent float64
	for _, c := range freq {
		ent += table[c]
	}

	maxEnt := ent
	var maxOff int

	// Slide: O(1) entropy update per step — adjust only the 2 affected bins.
	for i := 1; i <= n-ws; i++ {
		out := data[i-1]
		in := data[i+ws-1]

		if out != in {
			// Remove old contributions, update freq, add new contributions.
			ent -= table[freq[out]]
			freq[out]--
			ent += table[freq[out]]

			ent -= table[freq[in]]
			freq[in]++
			ent += table[freq[in]]
		}

		if ent > maxEnt {
			maxEnt = ent
			maxOff = i
		}
	}

	return EntropyResult{
		MaxEntropy: maxEnt,
		Offset:     maxOff,
		Flagged:    maxEnt >= a.Threshold,
	}
}

// shannonEntropy computes the Shannon entropy (bits per byte) of a byte slice.
// Returns 0.0 for nil or empty slices. Range: 0.0 to 8.0.
func shannonEntropy(data []byte) float64 {
	n := len(data)
	if n == 0 {
		return 0.0
	}

	var freq [256]int
	for _, b := range data {
		freq[b]++
	}

	total := float64(n)
	var entropy float64
	for _, count := range freq {
		if count == 0 {
			continue
		}
		p := float64(count) / total
		entropy -= p * math.Log2(p)
	}

	return entropy
}
