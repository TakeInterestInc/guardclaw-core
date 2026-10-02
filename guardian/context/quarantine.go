// Copyright 2025-2026 TakeInterest Inc.
// SPDX-License-Identifier: Apache-2.0

package context

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"
)

// quarantineState represents the persisted quarantine status.
type quarantineState struct {
	Active    bool      `json:"active"`
	Reason    string    `json:"reason"`
	Timestamp time.Time `json:"timestamp"`
}

// QuarantineManager controls observe-only mode when context files
// are modified outside a GuardClaw-supervised session.
type QuarantineManager struct {
	path  string
	state quarantineState
}

// NewQuarantineManager creates a QuarantineManager that persists state to path.
func NewQuarantineManager(path string) *QuarantineManager {
	return &QuarantineManager{path: path}
}

// IsQuarantined returns true if the session is in quarantine mode.
func (qm *QuarantineManager) IsQuarantined() bool {
	return qm.state.Active
}

// Reason returns the reason for quarantine, or empty if not quarantined.
func (qm *QuarantineManager) Reason() string {
	return qm.state.Reason
}

// Trigger activates quarantine mode with the given reason.
func (qm *QuarantineManager) Trigger(reason string) {
	qm.state = quarantineState{
		Active:    true,
		Reason:    reason,
		Timestamp: time.Now().UTC(),
	}
}

// Clear exits quarantine mode.
func (qm *QuarantineManager) Clear() {
	qm.state = quarantineState{}
}

// Save persists the quarantine state to disk.
func (qm *QuarantineManager) Save() error {
	data, err := json.MarshalIndent(qm.state, "", "  ")
	if err != nil {
		return err
	}
	if dir := filepath.Dir(qm.path); dir != "" {
		os.MkdirAll(dir, 0700)
	}
	return os.WriteFile(qm.path, data, 0600)
}

// Load reads the quarantine state from disk.
func (qm *QuarantineManager) Load() error {
	data, err := os.ReadFile(qm.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	return json.Unmarshal(data, &qm.state)
}
