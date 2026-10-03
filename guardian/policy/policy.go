// Copyright 2026 TakeInterest Inc.
// SPDX-License-Identifier: Apache-2.0

// Package policy implements exact-tool personal policy, independent of the
// pattern engine. An allow means no added restriction, never host approval.
package policy

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"regexp"
)

type Policy struct {
	Version int               `json:"version"`
	Default string            `json:"default"`
	Tools   map[string]string `json:"tools"`
}

var Name = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)

func decision(s string) bool { return s == "allow" || s == "deny" || s == "ask" }
func Load(r io.Reader) (Policy, error) {
	var p Policy
	data, err := io.ReadAll(io.LimitReader(r, (1<<20)+1))
	if err != nil || len(data) > 1<<20 {
		return p, errors.New("invalid or oversized personal policy")
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if err := d.Decode(&p); err != nil {
		return p, errors.New("invalid personal policy JSON")
	}
	var extra any
	if err := d.Decode(&extra); err != io.EOF {
		return p, errors.New("trailing policy data")
	}
	if p.Version != 1 || !decision(p.Default) || p.Tools == nil {
		return p, errors.New("policy needs version 1, default allow/deny/ask and tools object")
	}
	for tool, value := range p.Tools {
		if !Name.MatchString(tool) || !decision(value) {
			return p, errors.New("policy tool names must be exact identifiers and values allow/deny/ask")
		}
	}
	return p, nil
}
func (p Policy) Check(tool string) string {
	if v, ok := p.Tools[tool]; ok {
		return v
	}
	return p.Default
}
func (p Policy) ReceiptTool(tool string) string {
	if _, ok := p.Tools[tool]; ok && Name.MatchString(tool) {
		return tool
	}
	return "unmapped"
}
