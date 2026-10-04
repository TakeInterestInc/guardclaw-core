// Copyright 2025-2026 TakeInterest Inc.
// SPDX-License-Identifier: Apache-2.0
package security

import (
	"encoding/json"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

func credentialLabels() []string {
	return []string{"password", "passwd", "pwd", "secret", "api_key", "API-KEY", "access_token", "AccessToken", "client_secret", "auth_token", "bearer_token", "app_secret", "master_key", "signing_key", "encryption_key"}
}

func TestStructuredCredentialPIIAndPrePolicy(t *testing.T) {
	d := NewPIIDetector()
	// All values are synthetic markers. Include a recognized prefix followed by
	// punctuation, escaping and PII: the whole credential must be removed.
	for _, key := range credentialLabels() {
		for i, value := range []string{"demo_fixture_tail", "demo_fixture_tail!suffix", "demo_fixture_tail\"suffix", "demo_fixture_tail\\suffix", "demo_fixture_tail\nsuffix", "demo_fixture_tail$alice@example.com!suffix"} {
			t.Run(key+"/"+strconv.Itoa(i), func(t *testing.T) {
				if len(d.Detect(key+"="+value)) == 0 {
					t.Fatal("assignment control was not detected")
				}
				input := map[string]any{"outer": []any{[]any{map[string]any{key: value, "label": "routine text"}}}}
				before, _ := json.Marshal(input)
				if len(d.DetectInMap(input)) == 0 {
					t.Fatal("field context lost in nested map")
				}
				out := d.RedactMap(input)
				field := out["outer"].([]any)[0].([]any)[0].(map[string]any)
				if field[key] != "[PII REDACTED]" || field["label"] != "routine text" {
					t.Fatal("credential not fully removed or sibling changed")
				}
				pre := ValidatePrePolicyInput(input, PrePolicyConfig{})
				if len(pre.PIIMatches) == 0 || !reflect.DeepEqual(pre.SanitizedMap, out) {
					t.Fatal("default prepolicy failed to redact")
				}
				for _, mode := range []PIIMode{PIIModeOff, PIIModeMonitor} {
					pre = ValidatePrePolicyInput(input, PrePolicyConfig{PIIMode: mode})
					if pre.SanitizedMap != nil || (mode == PIIModeOff && len(pre.PIIMatches) != 0) || (mode == PIIModeMonitor && len(pre.PIIMatches) == 0) {
						t.Fatal("explicit PII mode changed")
					}
				}
				after, _ := json.Marshal(input)
				if string(before) != string(after) {
					t.Fatal("caller input mutated")
				}
			})
		}
	}
}

func TestStructuredCredentialEgress(t *testing.T) {
	e := NewEgressScanner()
	for _, key := range credentialLabels() {
		input := map[string]any{key: "demo_fixture_tail!suffix", "label": "routine text"}
		out, result := e.ScanMap(input)
		if out[key] != "[PII REDACTED]" || out["label"] != "routine text" || len(result.Findings) == 0 {
			t.Fatal("structured egress lost credential context")
		}
		encoded, _ := json.Marshal(result)
		if strings.Contains(string(encoded), "demo_fixture") || strings.Contains(string(encoded), "suffix") {
			t.Fatal("egress findings exported selected content")
		}
		for _, value := range []any{input, []any{[]any{input}}} {
			raw, _ := json.Marshal(value)
			redacted, result := e.ScanJSON(string(raw))
			if !json.Valid([]byte(redacted)) || strings.Contains(redacted, "demo_fixture") || strings.Contains(redacted, "suffix") || len(result.Findings) == 0 {
				t.Fatal("JSON egress failed to remove entire credential")
			}
		}
	}
	// JSON escapes must be decoded before applying field-aware detection.
	for _, raw := range []string{`{"api\u005fkey":"demo\u005ffixture_tail!suffix"}`, `[{"access\u005ftoken":"demo_fixture_tail\nsuffix"}]`, `{"api_key":[["demo_fixture_tail!suffix"]]}`} {
		out, result := e.ScanJSON(raw)
		if !json.Valid([]byte(out)) || strings.Contains(out, "demo") || strings.Contains(out, "suffix") || len(result.Findings) == 0 {
			t.Fatal("escaped or array-valued credential survived")
		}
	}
	for _, raw := range []string{`{"api_key":"demo_fixture_tail"}`, `{'access_token': 'demo_fixture_tail'}`, `api_key = demo_fixture_tail`} {
		out, result := e.ScanString(raw)
		if strings.Contains(out, "demo_fixture_tail") || len(result.Findings) == 0 {
			t.Fatal("quoted-key generic credential survived text scanning")
		}
	}
}

func TestStructuredCredentialControls(t *testing.T) {
	d := NewPIIDetector()
	e := NewEgressScanner()
	clean := map[string]any{
		"label": "routine text", "api_key": "", "access_token": "short",
		"password_required": true, "retries": float64(7), "optional": nil,
		"flags":      []any{true, nil, float64(7), "routine text"},
		"public_key": "demo_fixture_tail", "alice@example.com": "routine text",
		"description": "api_key", "nested": map[string]any{"enabled": false},
	}
	if len(d.DetectInMap(clean)) != 0 || !reflect.DeepEqual(d.RedactMap(clean), clean) {
		t.Fatal("clean fields or PII-shaped keys reinterpreted")
	}
	if pre := ValidatePrePolicyInput(clean, PrePolicyConfig{}); pre.SanitizedMap != nil || len(pre.PIIMatches) != 0 {
		t.Fatal("clean prepolicy input changed")
	}
	if out, result := e.ScanMap(clean); !reflect.DeepEqual(out, clean) || len(result.Findings) != 0 {
		t.Fatal("clean egress input changed")
	}
	// Independent leaf scanning and the existing service-account context remain.
	for _, input := range []map[string]any{{"label": "alice@example.com"}, {"type": "service_account"}, {"password": []any{[]any{"demo_fixture_tail!suffix"}}}} {
		if len(d.DetectInMap(input)) == 0 || reflect.DeepEqual(d.RedactMap(input), input) {
			t.Fatal("existing or array field detection lost")
		}
		if out, result := e.ScanMap(input); reflect.DeepEqual(out, input) || len(result.Findings) == 0 {
			t.Fatal("egress context or leaf scanning lost")
		}
	}
}

func TestStructuredCredentialNonsecretScalarControls(t *testing.T) {
	d := NewPIIDetector()
	e := NewEgressScanner()
	for _, value := range []any{nil, true, false, []any{nil, true, false}} {
		input := map[string]any{"password": value}
		if len(d.DetectInMap(input)) != 0 || !reflect.DeepEqual(d.RedactMap(input), input) {
			t.Fatal("noncredential typed control redacted")
		}
		if pre := ValidatePrePolicyInput(input, PrePolicyConfig{}); len(pre.PIIMatches) != 0 || pre.SanitizedMap != nil {
			t.Fatal("noncredential prepolicy control redacted")
		}
		if out, result := e.ScanMap(input); !reflect.DeepEqual(out, input) || len(result.Findings) != 0 {
			t.Fatal("noncredential egress control redacted")
		}
	}
	// Typed boolean controls are distinct from actual string passwords.
	for _, value := range []string{"true", "false", "null"} {
		input := map[string]any{"password": value}
		if len(d.DetectInMap(input)) == 0 || d.RedactMap(input)["password"] != "[PII REDACTED]" {
			t.Fatal("string password reinterpreted as a typed control")
		}
	}
}

func TestStructuredCredentialNumericRepresentation(t *testing.T) {
	d := NewPIIDetector()
	e := NewEgressScanner()
	for _, key := range []string{"api_key", "access_token"} {
		for _, number := range []string{"1000000000000000000000", "1e21", "-1e21", "0.000000000001"} {
			raw := `{"` + key + `":` + number + `}`
			var input map[string]any
			if err := json.Unmarshal([]byte(raw), &input); err != nil {
				t.Fatal("invalid synthetic JSON fixture")
			}
			if len(d.DetectInMap(input)) == 0 || d.RedactMap(input)[key] != "[PII REDACTED]" {
				t.Fatal("numeric credential lost through JSON formatting")
			}
			if pre := ValidatePrePolicyInput(input, PrePolicyConfig{}); len(pre.PIIMatches) == 0 || pre.SanitizedMap == nil || pre.SanitizedMap[key] != "[PII REDACTED]" {
				t.Fatal("prepolicy numeric credential missed")
			}
			if out, result := e.ScanJSON(raw); strings.Contains(out, "e+") || strings.Contains(out, "e-") || len(result.Findings) == 0 {
				t.Fatal("numeric JSON egress credential missed")
			}
		}
	}
}
