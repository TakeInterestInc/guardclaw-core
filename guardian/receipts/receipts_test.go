// Copyright 2026 TakeInterest Inc.
// SPDX-License-Identifier: Apache-2.0
package receipts

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func sample() Record {
	return Record{Host: "claude-code", Event: "decision", ActionID: strings.Repeat("1", 32), Tool: "Bash", Decision: "ask", Rule: "personal_policy", Outcome: "pending"}
}
func TestChainCorruptionAndTrustedAnchor(t *testing.T) {
	path := filepath.Join(t.TempDir(), "receipts.jsonl")
	var last Record
	for i := 0; i < 3; i++ {
		var err error
		last, err = Append(path, sample())
		if err != nil {
			t.Fatal(err)
		}
	}
	data, _ := os.ReadFile(path)
	anchor := &Checkpoint{last.ChainID, last.Sequence, last.Hash}
	if _, err := Verify(bytes.NewReader(data), anchor); err != nil {
		t.Fatal(err)
	}
	lines := bytes.SplitAfter(data, []byte("\n"))
	cases := map[string][]byte{
		"edited":         bytes.Replace(data, []byte(`"ask"`), []byte(`"deny"`), 1),
		"reordered":      bytes.Join([][]byte{lines[1], lines[0], lines[2]}, nil),
		"duplicate":      bytes.Join([][]byte{lines[0], lines[0], lines[1], lines[2]}, nil),
		"partial":        data[:len(data)-2],
		"blank":          append(append([]byte{}, data...), '\n'),
		"unknown":        bytes.Replace(data, []byte(`"schema":`), []byte(`"extra":0,"schema":`), 1),
		"duplicate_key":  bytes.Replace(data, []byte(`"sequence":1`), []byte(`"sequence":1,"sequence":1`), 1),
		"suffix_deleted": bytes.Join(lines[:2], nil),
		"all_deleted":    nil,
	}
	for name, data := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Verify(bytes.NewReader(data), anchor); err == nil {
				t.Fatal("accepted corrupted or truncated chain")
			}
		})
	}
	prefix := bytes.Join(lines[:2], nil)
	if _, err := Verify(bytes.NewReader(prefix), nil); err != nil {
		t.Fatal("intact prefix must be explicitly unverifiable without trusted anchor", err)
	}
	rewrite := filepath.Join(t.TempDir(), "other.jsonl")
	for i := 0; i < 3; i++ {
		if _, err := Append(rewrite, sample()); err != nil {
			t.Fatal(err)
		}
	}
	rewritten, _ := os.ReadFile(rewrite)
	if _, err := Verify(bytes.NewReader(rewritten), anchor); err == nil {
		t.Fatal("accepted full rewrite against anchor")
	}
	if _, err := Append(path, Record{Host: "bad\nsecret"}); err == nil {
		t.Fatal("accepted arbitrary metadata")
	}
}
func TestConcurrentAppendAndUnsafeFiles(t *testing.T) {
	path := filepath.Join(t.TempDir(), "journal")
	var wg sync.WaitGroup
	errs := make(chan error, 24)
	for i := 0; i < 24; i++ {
		wg.Go(func() { _, err := Append(path, sample()); errs <- err })
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	f, _ := os.Open(path)
	defer f.Close()
	tip, err := Verify(f, nil)
	if err != nil || tip.Sequence != 24 {
		t.Fatalf("tip=%+v err=%v", tip, err)
	}
	link := path + ".link"
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := Append(link, sample()); err == nil {
		t.Fatal("followed journal symlink")
	}
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := Append(path, sample()); err == nil {
		t.Fatal("accepted readable-by-others journal")
	}
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("partial"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Append(path, sample()); err == nil {
		t.Fatal("appended after partial write")
	}
}
func TestCrossLanguageVectors(t *testing.T) {
	b, err := os.ReadFile("testdata/canonical-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var vectors []struct {
		Name      string `json:"name"`
		Record    Record `json:"record"`
		Canonical string `json:"canonical_without_hash"`
		Hash      string `json:"sha256"`
		Valid     bool   `json:"valid_record"`
	}
	if err := json.Unmarshal(b, &vectors); err != nil {
		t.Fatal(err)
	}
	for _, v := range vectors {
		t.Run(v.Name, func(t *testing.T) {
			b, err := Canonical(v.Record, false)
			if err != nil || string(b) != v.Canonical {
				t.Fatalf("canonical mismatch %s %v", b, err)
			}
			h, _ := sum(v.Record)
			if h != v.Hash {
				t.Fatal("hash mismatch")
			}
			if valid(v.Record) != v.Valid {
				t.Fatal("validity mismatch")
			}
		})
	}
	b, err = os.ReadFile("testdata/verification-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var checks []struct {
		Name       string      `json:"name"`
		Journal    string      `json:"journal"`
		Checkpoint *Checkpoint `json:"checkpoint"`
		Accept     bool        `json:"accept"`
	}
	if err := json.Unmarshal(b, &checks); err != nil {
		t.Fatal(err)
	}
	for _, v := range checks {
		t.Run(v.Name, func(t *testing.T) {
			_, err := Verify(strings.NewReader(v.Journal), v.Checkpoint)
			if (err == nil) != v.Accept {
				t.Fatalf("accept=%v err=%v", v.Accept, err)
			}
		})
	}
}
