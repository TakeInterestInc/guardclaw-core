// Copyright 2025-2026 TakeInterest Inc.
// SPDX-License-Identifier: Apache-2.0

package tiered

import (
	"fmt"
	"strings"
	"testing"
)

// Run with -bench=BenchmarkScanMultiCommand -benchmem. This is deliberately
// per-event work, not an assertion of fixed latency on every host.
func BenchmarkScanMultiCommand(b *testing.B) {
	engine, err := NewEngine(nil)
	if err != nil {
		b.Fatal(err)
	}
	for _, size := range []int{4 << 10, 16 << 10, 64 << 10} {
		b.Run(fmt.Sprintf("%dKiB", size>>10), func(b *testing.B) {
			fragment := "systemctl status nginx; kill -9 $(pgrep -f 'node.*claude') | tee log; "
			input := strings.Repeat(fragment, size/len(fragment)+1)[:size]
			b.SetBytes(int64(size))
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				engine.Scan(input)
			}
		})
	}
}
