// Copyright 2025-2026 TakeInterest Inc.
// SPDX-License-Identifier: Apache-2.0

// Package context provides context file integrity checking for OWASP ASI06
// (Memory & Context Poisoning) protection.
package context

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
)

// contextDirs are the directories scanned for integrity checking.
var contextDirs = []string{
	".claude",
	".guardclaw",
	"memories",
}

// FileHash stores the path and SHA-256 hash of a context file.
type FileHash struct {
	Path string `json:"path"`
	Hash string `json:"hash"`
}

// Manifest stores the hash state of all context files.
type Manifest struct {
	Files map[string]string `json:"files"` // relPath → SHA-256 hash
}

// CheckResult reports the outcome of an integrity check.
type CheckResult struct {
	Tampered   bool     `json:"tampered"`
	IsFirstRun bool     `json:"is_first_run"`
	Changed    []string `json:"changed,omitempty"`
	Added      []string `json:"added,omitempty"`
	Removed    []string `json:"removed,omitempty"`
	TotalFiles int      `json:"total_files"`
}

// IntegrityChecker scans context directories for file tampering.
type IntegrityChecker struct {
	manifestPath string
	previous     *Manifest
	current      *Manifest
}

// NewIntegrityChecker creates a checker that persists its manifest at the given path.
func NewIntegrityChecker(manifestPath string) *IntegrityChecker {
	return &IntegrityChecker{
		manifestPath: manifestPath,
	}
}

// Check scans context directories under projectDir and compares against
// the previously saved manifest.
func (ic *IntegrityChecker) Check(projectDir string) (*CheckResult, error) {
	// Load previous manifest if it exists.
	ic.previous = ic.loadManifest()

	// Build current file hashes.
	ic.current = &Manifest{
		Files: make(map[string]string),
	}

	for _, dir := range contextDirs {
		dirPath := filepath.Join(projectDir, dir)
		if _, err := os.Stat(dirPath); os.IsNotExist(err) {
			continue
		}
		filepath.Walk(dirPath, func(path string, info os.FileInfo, err error) error { //nolint:errcheck // best-effort walk
			if err != nil || info.IsDir() {
				return nil //nolint:nilerr // filepath.Walk callback: skip inaccessible entries, continue walking
			}
			relPath, _ := filepath.Rel(projectDir, path)
			hash, hashErr := hashFile(path)
			if hashErr != nil {
				return nil //nolint:nilerr // skip unhashable files, continue walking
			}
			ic.current.Files[relPath] = hash
			return nil
		})
	}

	result := &CheckResult{
		TotalFiles: len(ic.current.Files),
	}

	if ic.previous == nil {
		result.IsFirstRun = true
		return result, nil
	}

	// Compare current vs previous.
	for path, hash := range ic.current.Files {
		prevHash, exists := ic.previous.Files[path]
		if !exists {
			result.Added = append(result.Added, path)
		} else if hash != prevHash {
			result.Changed = append(result.Changed, path)
		}
	}
	for path := range ic.previous.Files {
		if _, exists := ic.current.Files[path]; !exists {
			result.Removed = append(result.Removed, path)
		}
	}

	result.Tampered = len(result.Changed) > 0 || len(result.Added) > 0 || len(result.Removed) > 0
	return result, nil
}

// SaveManifest persists the current manifest to disk.
func (ic *IntegrityChecker) SaveManifest() error {
	if ic.current == nil {
		return nil
	}
	data, err := json.MarshalIndent(ic.current, "", "  ")
	if err != nil {
		return err
	}
	if dir := filepath.Dir(ic.manifestPath); dir != "" {
		os.MkdirAll(dir, 0700)
	}
	return os.WriteFile(ic.manifestPath, data, 0600)
}

// loadManifest reads the previously saved manifest, or nil if not found.
func (ic *IntegrityChecker) loadManifest() *Manifest {
	data, err := os.ReadFile(ic.manifestPath)
	if err != nil {
		return nil
	}
	var m Manifest
	if json.Unmarshal(data, &m) != nil {
		return nil
	}
	return &m
}

// hashFile computes the SHA-256 hash of a file.
func hashFile(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:]), nil
}

// TamperSummary returns a human-readable summary of detected changes.
func (r *CheckResult) TamperSummary() string {
	if !r.Tampered {
		return "no changes detected"
	}
	var parts []string
	if len(r.Changed) > 0 {
		parts = append(parts, strings.Join(r.Changed, ", ")+" modified")
	}
	if len(r.Added) > 0 {
		parts = append(parts, strings.Join(r.Added, ", ")+" added")
	}
	if len(r.Removed) > 0 {
		parts = append(parts, strings.Join(r.Removed, ", ")+" removed")
	}
	return strings.Join(parts, "; ")
}
