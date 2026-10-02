// Copyright 2025-2026 TakeInterest Inc.
// SPDX-License-Identifier: Apache-2.0

package security

import (
	"net"
	"testing"
)

// stubLookup replaces the system resolver for one test and counts calls, so a
// test can prove a code path did or did not resolve DNS.
func stubLookup(t *testing.T, ips ...string) *int {
	t.Helper()
	calls := 0
	orig := netLookupIP
	netLookupIP = func(host string) ([]net.IP, error) {
		calls++
		out := make([]net.IP, 0, len(ips))
		for _, s := range ips {
			out = append(out, net.ParseIP(s))
		}
		return out, nil
	}
	t.Cleanup(func() { netLookupIP = orig })
	return &calls
}

func TestURLValidatorDefaultMakesNoDNSLookup(t *testing.T) {
	calls := stubLookup(t, "10.0.0.5")

	v := NewURLValidator()
	r := v.Validate("https://internal.example.com/data")
	if !r.Valid {
		t.Fatalf("hostname judged invalid without resolution: %+v", r)
	}
	if len(r.ResolvedIPs) != 0 {
		t.Fatalf("default validator reported resolved IPs: %v", r.ResolvedIPs)
	}
	_ = v.IsSafe("https://another.example.org/")
	_ = v.ValidateMany([]string{"https://a.example.net/", "http://b.example.net/x"})

	// Every in-package caller of the validator must stay offline by default.
	_, _ = NewEgressScanner().ScanString("see https://c.example.com/report for details")
	_ = ValidatePrePolicyInput(map[string]any{"url": "https://d.example.com/"}, PrePolicyConfig{PIIMode: PIIModeOff})
	_ = ExportAllPatterns()

	if *calls != 0 {
		t.Fatalf("default path performed %d DNS lookup(s); want 0", *calls)
	}
}

func TestURLValidatorDNSResolutionIsOptIn(t *testing.T) {
	calls := stubLookup(t, "10.0.0.5")

	r := NewURLValidator().EnableDNSResolution().Validate("https://rebind.example.com/")
	if *calls != 1 {
		t.Fatalf("opt-in validator made %d lookups; want 1", *calls)
	}
	if r.Valid {
		t.Fatalf("hostname resolving to a private IP was judged valid: %+v", r)
	}
	found := false
	for _, th := range r.Threats {
		if th == ThreatDNSRebind {
			found = true
		}
	}
	if !found {
		t.Fatalf("want ThreatDNSRebind, got %v", r.Threats)
	}

	// IP literals are never resolved, even when resolution is on.
	_ = NewURLValidator().EnableDNSResolution().Validate("https://93.184.216.34/")
	if *calls != 1 {
		t.Fatalf("IP literal triggered a lookup; calls=%d", *calls)
	}
}

func TestURLValidatorSetResolver(t *testing.T) {
	calls := stubLookup(t)
	custom := 0
	v := NewURLValidator().SetResolver(func(string) ([]net.IP, error) {
		custom++
		return []net.IP{net.ParseIP("127.0.0.1")}, nil
	})
	if r := v.Validate("https://loop.example.com/"); r.Valid {
		t.Fatalf("loopback resolution judged valid: %+v", r)
	}
	if custom != 1 || *calls != 0 {
		t.Fatalf("custom=%d system=%d; want 1 and 0", custom, *calls)
	}
	v.SetResolver(nil)
	if r := v.Validate("https://loop.example.com/"); !r.Valid || custom != 1 {
		t.Fatalf("SetResolver(nil) did not turn resolution off: valid=%v custom=%d", r.Valid, custom)
	}
}
