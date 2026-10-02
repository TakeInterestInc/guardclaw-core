// Copyright 2025-2026 TakeInterest Inc.
// SPDX-License-Identifier: Apache-2.0

package tiered

import (
	"fmt"
	"runtime"
	"sync"
)

const (
	// DefaultMemoryBudget is the Phase 1 memory budget in bytes (65 MB).
	// Design doc §7.6 line 2030: "~40-65 MB".
	DefaultMemoryBudget uint64 = 65 * 1024 * 1024

	// MinMemoryBudget is the minimum allowed budget (1 MB) to prevent
	// nonsensical configurations that would always trigger warnings.
	MinMemoryBudget uint64 = 1024 * 1024
)

// ResourceAccountant tracks daemon memory usage against a configurable budget.
// It serializes ReadMemStats calls to avoid redundant stop-the-world pauses.
type ResourceAccountant struct {
	budget uint64
	mu     sync.Mutex
}

// ResourceStatus holds the result of a memory check.
type ResourceStatus struct {
	RSS     uint64  // current memory obtained from OS (runtime.MemStats.Sys)
	Budget  uint64  // configured budget in bytes
	Used    float64 // usage ratio: RSS / Budget (can exceed 1.0)
	Warning bool    // true if RSS >= Budget
	Message string  // human-readable warning; empty if within budget
}

// NewResourceAccountant returns an accountant with the default 65 MB budget.
func NewResourceAccountant() *ResourceAccountant {
	return &ResourceAccountant{budget: DefaultMemoryBudget}
}

// WithBudget returns a copy with a custom budget (clamped to MinMemoryBudget floor).
func (r *ResourceAccountant) WithBudget(bytes uint64) *ResourceAccountant {
	if bytes < MinMemoryBudget {
		bytes = MinMemoryBudget
	}
	return &ResourceAccountant{budget: bytes}
}

// Check reads current memory stats and returns the resource status.
// Safe for concurrent use; serializes ReadMemStats calls via mutex.
func (r *ResourceAccountant) Check() ResourceStatus {
	var ms runtime.MemStats
	r.mu.Lock()
	runtime.ReadMemStats(&ms)
	r.mu.Unlock()

	rss := ms.Sys
	used := float64(rss) / float64(r.budget)
	warning := rss >= r.budget

	var msg string
	if warning {
		msg = fmt.Sprintf("memory budget exceeded: using %d MB of %d MB budget (%.1f%%)",
			rss/(1024*1024), r.budget/(1024*1024), used*100)
	}

	return ResourceStatus{
		RSS:     rss,
		Budget:  r.budget,
		Used:    used,
		Warning: warning,
		Message: msg,
	}
}
