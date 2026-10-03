// SPDX-License-Identifier: Apache-2.0
package report

import (
	"bytes"
	"encoding/json"
	"io"
	"regexp"
	"strconv"
	"time"
	"unicode/utf8"
)

// ValidationError exposes only a fixed code, never parser text or input values.
type ValidationError struct{ Code string }

func (e *ValidationError) Error() string { return e.Code }
func invalid() error                     { return &ValidationError{Code: "REPORT_INVALID"} }

// strictValue bounds container depth and rejects duplicate keys and noninteger
// numeric tokens before ordinary typed decoding can lose that information.
func strictValue(d *json.Decoder, depth int) (any, error) {
	t, err := d.Token()
	if err != nil {
		return nil, invalid()
	}
	if delim, ok := t.(json.Delim); ok {
		if depth > 6 {
			return nil, invalid()
		}
		switch delim {
		case '{':
			m := map[string]any{}
			for d.More() {
				key, err := d.Token()
				if err != nil {
					return nil, invalid()
				}
				k, ok := key.(string)
				if !ok {
					return nil, invalid()
				}
				if _, ok := m[k]; ok {
					return nil, invalid()
				}
				v, err := strictValue(d, depth+1)
				if err != nil {
					return nil, err
				}
				m[k] = v
			}
			end, err := d.Token()
			if err != nil || end != json.Delim('}') {
				return nil, invalid()
			}
			return m, nil
		case '[':
			a := []any{}
			for d.More() {
				v, err := strictValue(d, depth+1)
				if err != nil {
					return nil, err
				}
				a = append(a, v)
			}
			end, err := d.Token()
			if err != nil || end != json.Delim(']') {
				return nil, invalid()
			}
			return a, nil
		default:
			return nil, invalid()
		}
	}
	if n, ok := t.(json.Number); ok {
		v, err := strconv.ParseInt(string(n), 10, 64)
		if err != nil || v > int64(MaxRevision) || v < -int64(MaxRevision) {
			return nil, invalid()
		}
	}
	return t, nil
}

func required(v any, keys ...string) bool {
	m, ok := v.(map[string]any)
	if !ok || len(m) != len(keys) {
		return false
	}
	for _, k := range keys {
		if _, ok := m[k]; !ok {
			return false
		}
	}
	return true
}

// ValidateBytes validates an untrusted report, not its truth or authenticity.
// Numeric fields must use integer tokens, without decimal/exponent notation.
func ValidateBytes(data []byte) (Report, error) {
	var r Report
	if len(data) > MaxOutput {
		return r, &ValidationError{Code: "REPORT_TOO_LARGE"}
	}
	if !utf8.Valid(data) {
		return r, invalid()
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	v, err := strictValue(d, 1)
	if err != nil {
		return r, invalid()
	}
	if _, err = d.Token(); err != io.EOF {
		return r, invalid()
	}
	if !required(v, "schema_version", "engine", "subject", "started_at", "finished_at", "status", "outcome", "coverage", "findings", "error") {
		return r, invalid()
	}
	m := v.(map[string]any)
	if !required(m["engine"], "module", "baseline_tree", "mode") || !required(m["coverage"], "mode", "input_bytes", "total_lines", "scanned_lines", "blank_lines") {
		return r, invalid()
	}
	if m["subject"] != nil && !required(m["subject"], "snapshot_id", "revision") {
		return r, invalid()
	}
	if m["subject"] != nil {
		// encoding/json would otherwise turn a null uint64 into zero.
		if _, ok := m["subject"].(map[string]any)["revision"].(json.Number); !ok {
			return r, invalid()
		}
	}
	if m["error"] != nil && !required(m["error"], "code") {
		return r, invalid()
	}
	f, ok := m["findings"].([]any)
	if !ok || len(f) > MaxFindings {
		return r, invalid()
	}
	for _, item := range f {
		if !required(item, "line", "decision", "severity", "pattern_ids") {
			return r, invalid()
		}
	}
	d = json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if d.Decode(&r) != nil {
		return Report{}, invalid()
	}
	if r.SchemaVersion != Version {
		return Report{}, &ValidationError{Code: "REPORT_UNSUPPORTED"}
	}
	if err = validateReport(r); err != nil {
		return Report{}, err
	}
	return r, nil
}

var utcPattern = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]{1,6})?Z$`)

func parseTime(v string) (time.Time, error) {
	if len(v) > 27 || !utcPattern.MatchString(v) {
		return time.Time{}, invalid()
	}
	t, err := time.Parse(time.RFC3339Nano, v)
	if err != nil || t.Year() < 1 {
		return time.Time{}, invalid()
	}
	return t, nil
}
func validateSubject(s *Subject) bool {
	return s != nil && len(s.SnapshotID) == 36 && uuidPattern.MatchString(s.SnapshotID) && s.Revision <= MaxRevision
}
func validateReport(r Report) error {
	if r.SchemaVersion != Version || r.Engine != (EngineIdentity{Module, BaselineTree, EngineMode}) || r.Coverage.Mode != CoverageMode || r.Findings == nil {
		return invalid()
	}
	start, err := parseTime(r.StartedAt)
	if err != nil {
		return invalid()
	}
	end, err := parseTime(r.FinishedAt)
	if err != nil || end.Before(start) {
		return invalid()
	}
	if r.Subject != nil && !validateSubject(r.Subject) {
		return invalid()
	}
	if len(r.Findings) > MaxFindings {
		return invalid()
	}
	if r.Error != nil && !errorSet[r.Error.Code] {
		return invalid()
	}
	counts := []*int{r.Coverage.InputBytes, r.Coverage.TotalLines, r.Coverage.ScannedLines, r.Coverage.BlankLines}
	if r.Status == "failed" {
		if r.Outcome != "unknown" || len(r.Findings) != 0 || r.Error == nil || r.Error.Code == "NO_CONTENT" {
			return invalid()
		}
		if (r.Subject == nil) != (r.Error.Code == "INVALID_METADATA") {
			return invalid()
		}
		for _, c := range counts {
			if c != nil {
				return invalid()
			}
		}
		return nil
	}
	if !validateSubject(r.Subject) {
		return invalid()
	}
	for _, c := range counts {
		if c == nil || *c < 0 {
			return invalid()
		}
	}
	b, total, scanned, blank := *counts[0], *counts[1], *counts[2], *counts[3]
	if b > MaxInput || total > MaxLines || scanned > MaxLines || blank > MaxLines || total != scanned+blank || b < total || (b == 0) != (total == 0) {
		return invalid()
	}
	if r.Status == "no_content" {
		if scanned != 0 || r.Outcome != "unknown" || len(r.Findings) != 0 || r.Error == nil || r.Error.Code != "NO_CONTENT" {
			return invalid()
		}
		return nil
	}
	if r.Status != "complete" || scanned < 1 || r.Error != nil || len(r.Findings) > scanned {
		return invalid()
	}
	if (len(r.Findings) == 0 && r.Outcome != "no_patterns_matched") || (len(r.Findings) > 0 && r.Outcome != "review_needed") {
		return invalid()
	}
	ids, err := registrySet()
	if err != nil {
		return invalid()
	}
	seen := map[int]bool{}
	for _, f := range r.Findings {
		if f.Line < 1 || f.Line > total || seen[f.Line] || (f.Decision != "deny" && f.Decision != "escalate") || !severitySet[f.Severity] || len(f.PatternIDs) < 1 || len(f.PatternIDs) > MaxPatternIDs {
			return invalid()
		}
		seen[f.Line] = true
		matched := map[string]bool{}
		for _, id := range f.PatternIDs {
			if !ids[id] || matched[id] {
				return invalid()
			}
			matched[id] = true
		}
	}
	return nil
}

type Assessment struct {
	State      string
	Provenance string
}

// AssessAttachment returns advisory visibility only. Even a perfectly shaped,
// matching report is unverified; this type contains no action authority.
func AssessAttachment(r Report, current Subject) Assessment {
	a := Assessment{State: "invalid_report", Provenance: "user_imported_unverified"}
	if validateReport(r) != nil || !validateSubject(&current) {
		return a
	}
	if r.Subject == nil {
		a.State = "unattached_error"
		return a
	}
	if r.Subject.SnapshotID != current.SnapshotID || r.Subject.Revision > current.Revision {
		a.State = "mismatch_unverified"
		return a
	}
	if r.Subject.Revision < current.Revision {
		a.State = "earlier_unverified"
		return a
	}
	a.State = "current_unverified"
	return a
}
