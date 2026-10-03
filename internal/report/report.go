// SPDX-License-Identifier: Apache-2.0
// Package report produces bounded advisory reports. It grants no action authority.
package report

import (
	"bytes"
	"encoding/json"
	"io"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/TakeInterestInc/guardclaw-core/guardian/tiered"
	"github.com/TakeInterestInc/guardclaw-core/schemas"
)

const (
	Version       = "guardclaw.scan-report.v1"
	BaselineTree  = "336faa083fccb78a098cf2cf146df3e4d50c1d82"
	Module        = "github.com/TakeInterestInc/guardclaw-core"
	EngineMode    = "static_line_scan"
	CoverageMode  = "all_nonblank_lines_including_comments"
	MaxInput      = 262144
	MaxOutput     = 65536
	MaxLines      = 1000
	MaxLine       = 16384
	MaxFindings   = 200
	MaxPatternIDs = 16
	MaxRevision   = uint64(9007199254740991)
)

type Subject struct {
	SnapshotID string `json:"snapshot_id"`
	Revision   uint64 `json:"revision"`
}
type EngineIdentity struct {
	Module       string `json:"module"`
	BaselineTree string `json:"baseline_tree"`
	Mode         string `json:"mode"`
}
type Coverage struct {
	Mode         string `json:"mode"`
	InputBytes   *int   `json:"input_bytes"`
	TotalLines   *int   `json:"total_lines"`
	ScannedLines *int   `json:"scanned_lines"`
	BlankLines   *int   `json:"blank_lines"`
}
type Finding struct {
	Line       int      `json:"line"`
	Decision   string   `json:"decision"`
	Severity   string   `json:"severity"`
	PatternIDs []string `json:"pattern_ids"`
}
type Error struct {
	Code string `json:"code"`
}
type Report struct {
	SchemaVersion string         `json:"schema_version"`
	Engine        EngineIdentity `json:"engine"`
	Subject       *Subject       `json:"subject"`
	StartedAt     string         `json:"started_at"`
	FinishedAt    string         `json:"finished_at"`
	Status        string         `json:"status"`
	Outcome       string         `json:"outcome"`
	Coverage      Coverage       `json:"coverage"`
	Findings      []Finding      `json:"findings"`
	Error         *Error         `json:"error"`
}

var uuidPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
var digitsPattern = regexp.MustCompile(`^[0-9]+$`)
var severitySet = map[string]bool{"critical": true, "high": true, "medium": true, "low": true, "info": true}
var errorSet = map[string]bool{
	"INVALID_METADATA": true, "INPUT_LIMIT": true, "INVALID_ENCODING": true, "NUL_BYTE": true,
	"LINE_LIMIT": true, "LINE_COUNT_LIMIT": true, "FINDING_LIMIT": true, "PATTERN_LIMIT": true,
	"OUTPUT_LIMIT": true, "ENGINE_UNAVAILABLE": true, "ENGINE_RESULT_INVALID": true,
	"TIMEOUT": true, "CANCELLED": true, "IO_ERROR": true, "NO_CONTENT": true,
}

func intPtr(n int) *int { return &n }
func timestamp() string { return time.Now().UTC().Format("2006-01-02T15:04:05.000000Z") }
func newReport(subject *Subject) Report {
	return Report{SchemaVersion: Version, Engine: EngineIdentity{Module, BaselineTree, EngineMode},
		Subject: subject, StartedAt: timestamp(), Status: "failed", Outcome: "unknown",
		Coverage: Coverage{Mode: CoverageMode}, Findings: []Finding{}, Error: &Error{Code: "IO_ERROR"}}
}
func failReport(r Report, code string) (Report, int) {
	r.Status = "failed"
	r.Outcome = "unknown"
	r.Error = &Error{Code: code}
	r.Coverage = Coverage{Mode: CoverageMode}
	r.Findings = []Finding{}
	if code == "INVALID_METADATA" {
		r.Subject = nil
	}
	r.FinishedAt = timestamp()
	// A backward wall-clock step must not emit a contradictory time interval.
	if r.FinishedAt < r.StartedAt {
		r.FinishedAt = r.StartedAt
	}
	return r, 2
}

// ParseSubject accepts only bounded metadata. Supplied values are never echoed.
func ParseSubject(args []string) (*Subject, error) {
	bad := &ValidationError{Code: "INVALID_METADATA"}
	if len(args) != 4 {
		return nil, bad
	}
	n := 0
	for _, a := range args {
		n += len(a)
		if n > 1024 {
			return nil, bad
		}
	}
	values := map[string]string{}
	for i := 0; i < 4; i += 2 {
		if args[i] != "--snapshot-id" && args[i] != "--revision" {
			return nil, bad
		}
		if _, ok := values[args[i]]; ok {
			return nil, bad
		}
		values[args[i]] = args[i+1]
	}
	id, revision := values["--snapshot-id"], values["--revision"]
	if len(id) != 36 || !uuidPattern.MatchString(id) || len(revision) > 16 || !digitsPattern.MatchString(revision) {
		return nil, bad
	}
	r, err := strconv.ParseUint(revision, 10, 64)
	if err != nil || r > MaxRevision {
		return nil, bad
	}
	return &Subject{SnapshotID: id, Revision: r}, nil
}

func registrySet() (map[string]bool, error) {
	var data struct {
		BaselineTree string   `json:"baseline_tree"`
		IDs          []string `json:"pattern_ids"`
	}
	if json.Unmarshal(schemas.PatternRegistry(), &data) != nil || data.BaselineTree != BaselineTree || len(data.IDs) != 1703 {
		return nil, &ValidationError{Code: "ENGINE_UNAVAILABLE"}
	}
	ids := make(map[string]bool, len(data.IDs))
	for _, id := range data.IDs {
		if ids[id] || id == "" {
			return nil, &ValidationError{Code: "ENGINE_UNAVAILABLE"}
		}
		ids[id] = true
	}
	return ids, nil
}

type scanner interface {
	Ready() bool
	Scan(string) tiered.ScanResult
}
type engineFactory func() (scanner, error)

func staticFactory() (scanner, error) { return tiered.NewEngine(nil) }

// Run reads stdin only and emits sanitized JSON. The command's independent
// watchdog must also cover readers/writers that never return.
func Run(args []string, input io.Reader, output io.Writer) int {
	return run(args, input, output, staticFactory, MaxOutput)
}

func run(args []string, input io.Reader, output io.Writer, factory engineFactory, outputCap int) (exit int) {
	subject, err := ParseSubject(args)
	r := newReport(subject)
	writing := false
	// Engine/parser panics must not expose stack traces or supplied strings.
	defer func() {
		if recover() != nil {
			exit = 2
			if !writing {
				r, _ = failReport(r, "ENGINE_RESULT_INVALID")
				_ = writeReport(output, r, MaxOutput)
			}
		}
	}()
	if err != nil {
		r, exit = failReport(r, "INVALID_METADATA")
		writing = true
		return emit(output, r, exit, outputCap)
	}
	r, exit = scanInput(r, input, factory)
	writing = true
	return emit(output, r, exit, outputCap)
}

func scanInput(r Report, input io.Reader, factory engineFactory) (Report, int) {
	data, err := io.ReadAll(io.LimitReader(input, MaxInput+1))
	if err != nil {
		return failReport(r, "IO_ERROR")
	}
	if len(data) > MaxInput {
		return failReport(r, "INPUT_LIMIT")
	}
	if !utf8.Valid(data) {
		return failReport(r, "INVALID_ENCODING")
	}
	if bytes.IndexByte(data, 0) >= 0 {
		return failReport(r, "NUL_BYTE")
	}
	var lines [][]byte
	if len(data) > 0 {
		lines = bytes.Split(data, []byte{'\n'})
		if data[len(data)-1] == '\n' {
			lines = lines[:len(lines)-1]
		}
	}
	if len(lines) > MaxLines {
		return failReport(r, "LINE_COUNT_LIMIT")
	}
	blank := 0
	for _, line := range lines {
		if len(line) > MaxLine {
			return failReport(r, "LINE_LIMIT")
		}
		if len(line) > 0 && line[len(line)-1] == '\r' {
			line = line[:len(line)-1]
		}
		if strings.Trim(string(line), " \t") == "" {
			blank++
		}
	}
	r.Coverage = Coverage{CoverageMode, intPtr(len(data)), intPtr(len(lines)), intPtr(len(lines) - blank), intPtr(blank)}
	if len(lines) == blank {
		r.Status = "no_content"
		r.Outcome = "unknown"
		r.Error = &Error{Code: "NO_CONTENT"}
		r.FinishedAt = timestamp()
		if r.FinishedAt < r.StartedAt {
			r.FinishedAt = r.StartedAt
		}
		return r, 2
	}
	ids, err := registrySet()
	if err != nil {
		return failReport(r, "ENGINE_UNAVAILABLE")
	}
	engine, err := factory()
	if err != nil || engine == nil || !engine.Ready() {
		return failReport(r, "ENGINE_UNAVAILABLE")
	}
	for i, line := range lines {
		if len(line) > 0 && line[len(line)-1] == '\r' {
			line = line[:len(line)-1]
		}
		if strings.Trim(string(line), " \t") == "" {
			continue
		}
		result := engine.Scan(string(line))
		if result.Decision == "allow" {
			continue
		}
		if (result.Decision != "deny" && result.Decision != "escalate") || !severitySet[result.Severity] {
			return failReport(r, "ENGINE_RESULT_INVALID")
		}
		matched := map[string]bool{}
		for _, id := range append(result.MatchedPatterns, result.PatternID) {
			if id != "" {
				if !ids[id] {
					return failReport(r, "ENGINE_RESULT_INVALID")
				}
				matched[id] = true
			}
		}
		if len(matched) == 0 {
			return failReport(r, "ENGINE_RESULT_INVALID")
		}
		if len(matched) > MaxPatternIDs {
			return failReport(r, "PATTERN_LIMIT")
		}
		list := make([]string, 0, len(matched))
		for id := range matched {
			list = append(list, id)
		}
		sort.Strings(list)
		r.Findings = append(r.Findings, Finding{i + 1, result.Decision, result.Severity, list})
		if len(r.Findings) > MaxFindings {
			return failReport(r, "FINDING_LIMIT")
		}
	}
	r.Status = "complete"
	r.Error = nil
	r.Outcome = "no_patterns_matched"
	exit := 0
	if len(r.Findings) > 0 {
		r.Outcome = "review_needed"
		exit = 1
	}
	r.FinishedAt = timestamp()
	if r.FinishedAt < r.StartedAt {
		r.FinishedAt = r.StartedAt
	}
	return r, exit
}

func encodedReport(r Report) ([]byte, error) {
	data, err := json.Marshal(r)
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}
func writeReport(w io.Writer, r Report, cap int) error {
	data, err := encodedReport(r)
	if err != nil {
		return &ValidationError{Code: "IO_ERROR"}
	}
	if len(data) > cap {
		return &ValidationError{Code: "OUTPUT_LIMIT"}
	}
	n, err := safeWrite(w, data)
	if err != nil || n != len(data) {
		return &ValidationError{Code: "IO_ERROR"}
	}
	return nil
}
func safeWrite(w io.Writer, data []byte) (n int, err error) {
	defer func() {
		if recover() != nil {
			n = 0
			err = &ValidationError{Code: "IO_ERROR"}
		}
	}()
	return w.Write(data)
}
func emit(w io.Writer, r Report, exit, cap int) int {
	data, err := encodedReport(r)
	if err != nil {
		return 2
	}
	if len(data) > cap {
		r, _ = failReport(r, "OUTPUT_LIMIT")
		if writeReport(w, r, MaxOutput) != nil {
			return 2
		}
		return 2
	}
	n, err := safeWrite(w, data)
	if err != nil || n != len(data) {
		return 2
	}
	return exit
}
