// Copyright 2025-2026 TakeInterest Inc.
// SPDX-License-Identifier: Apache-2.0

// Corpus evaluation: proves the tiered detection engine holds a low false-positive
// rate on benign inputs and a high detection rate on malicious inputs.
//
// Clean-room Apache implementation. It mirrors the proven evaluation CONTRACT
// (per-line scan, FP-rate and detection-rate thresholds) without copying any
// proprietary test source. Each non-comment, non-blank line of a corpus file is
// ONE input — matching how the engine is invoked per agent tool-call in practice
// (not a whole multi-line file scanned as a single blob).
package security_test

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/TakeInterestInc/guardclaw-core/guardian/tiered"
)

const (
	maxFPRate        = 0.01 // <=1% false positives on benign corpus
	minDetectionRate = 0.95 // >=95% of malicious inputs flagged

	// fakeMarker is removed from every corpus line before it is scanned.
	// See testdata/corpus/README.md.
	fakeMarker = "<FAKE>"
)

// loadCorpusLines reads a corpus dir, returning each meaningful line as one input.
// Lines that are blank or begin with '#' (comments) are skipped — they are corpus
// annotations, not inputs to scan.
func loadCorpusLines(t *testing.T, dir string) []string {
	t.Helper()
	var lines []string
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read corpus dir %s: %v", dir, err)
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".txt") {
			continue
		}
		f, err := os.Open(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatalf("open %s: %v", e.Name(), err)
		}
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			// Credential-shaped fixtures carry fakeMarker inside the token so
			// the file never holds a scanner-matching secret shape. The full
			// synthetic shape exists only in memory, here.
			lines = append(lines, strings.ReplaceAll(line, fakeMarker, ""))
		}
		_ = f.Close()
	}
	return lines
}

func newEngine(t *testing.T) *tiered.Engine {
	t.Helper()
	eng, err := tiered.NewEngine(nil)
	if err != nil {
		t.Fatalf("engine init: %v", err)
	}
	if !eng.Ready() {
		t.Fatal("engine not ready")
	}
	return eng
}

func TestCorpus_BenignFalsePositiveRate(t *testing.T) {
	eng := newEngine(t)
	benign := loadCorpusLines(t, filepath.Join("..", "..", "testdata", "corpus", "benign"))
	if len(benign) == 0 {
		t.Fatal("no benign corpus lines loaded")
	}
	var fps int
	for _, line := range benign {
		if eng.Scan(line).Decision == "deny" {
			fps++
			t.Logf("FP: %q", line)
		}
	}
	rate := float64(fps) / float64(len(benign))
	t.Logf("benign=%d fps=%d rate=%.4f (%.2f%%)", len(benign), fps, rate, rate*100)
	if rate > maxFPRate {
		t.Fatalf("FP rate %.4f exceeds %.4f", rate, maxFPRate)
	}
}

func TestCorpus_MaliciousDetectionRate(t *testing.T) {
	eng := newEngine(t)
	mal := loadCorpusLines(t, filepath.Join("..", "..", "testdata", "corpus", "malicious"))
	if len(mal) == 0 {
		t.Fatal("no malicious corpus lines loaded")
	}
	var detected int
	for _, line := range mal {
		if eng.Scan(line).Decision != "allow" {
			detected++
		} else {
			t.Logf("MISSED: %q", line)
		}
	}
	rate := float64(detected) / float64(len(mal))
	t.Logf("malicious=%d detected=%d rate=%.4f (%.2f%%)", len(mal), detected, rate, rate*100)
	if rate < minDetectionRate {
		t.Fatalf("detection rate %.4f below %.4f", rate, minDetectionRate)
	}
}

// TestCorpus_FakeMarkerRemovedBeforeScan pins the loader contract: the
// credential fixtures are stored with fakeMarker inside each token, and no line
// reaches the engine with the marker still in it.
func TestCorpus_FakeMarkerRemovedBeforeScan(t *testing.T) {
	dir := filepath.Join("..", "..", "testdata", "corpus", "malicious")
	raw, err := os.ReadFile(filepath.Join(dir, "secrets_pii.txt"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	if n := strings.Count(string(raw), fakeMarker); n < 10 {
		t.Fatalf("secrets_pii.txt carries %d %s markers; credential fixtures must keep them", n, fakeMarker)
	}
	for _, line := range loadCorpusLines(t, dir) {
		if strings.Contains(line, fakeMarker) {
			t.Fatalf("marker survived loading: %q", line)
		}
	}
}
