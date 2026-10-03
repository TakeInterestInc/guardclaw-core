// Copyright 2026 TakeInterest Inc.
// SPDX-License-Identifier: Apache-2.0

// Package receipts stores metadata-only, hash-chained decision observations.
// Hashes are integrity checks relative to a trusted checkpoint, not signatures.
package receipts

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

const Schema = "guardclaw.receipt.v1"
const Genesis = "0000000000000000000000000000000000000000000000000000000000000000"
const maxJournal = 64 << 20

// Record contains no arbitrary input, reason, path, result, recipient or body.
// Tool must be a configured identifier; unknown names are recorded as unmapped.
type Record struct {
	Schema    string `json:"schema"`
	ChainID   string `json:"chain_id"`
	Sequence  uint64 `json:"sequence"`
	PrevHash  string `json:"prev_hash"`
	Timestamp string `json:"timestamp"`
	Host      string `json:"host"`
	Event     string `json:"event"`
	ActionID  string `json:"action_id"`
	Tool      string `json:"tool"`
	Decision  string `json:"decision"`
	Rule      string `json:"rule"`
	Outcome   string `json:"outcome"`
	Redaction string `json:"redaction"`
	Hash      string `json:"hash"`
}
type Checkpoint struct {
	ChainID  string `json:"chain_id"`
	Sequence uint64 `json:"sequence"`
	Hash     string `json:"hash"`
}

var name = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)
var digest = regexp.MustCompile(`^[a-f0-9]{64}$`)
var chainID = regexp.MustCompile(`^[a-f0-9]{32}$`)

func ID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

// Canonical is compact UTF-8 Go JSON with lexicographically ordered object
// keys; HTML and U+2028/U+2029 escaping follows encoding/json. No floats.
func Canonical(r Record, withHash bool) ([]byte, error) {
	data, err := json.Marshal(r)
	if err != nil {
		return nil, err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return nil, err
	}
	if !withHash {
		delete(fields, "hash")
	}
	return json.Marshal(fields)
}
func sum(r Record) (string, error) {
	b, err := Canonical(r, false)
	if err != nil {
		return "", err
	}
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:]), nil
}
func valid(r Record) bool {
	stamp, err := time.Parse(time.RFC3339Nano, r.Timestamp)
	return err == nil && stamp.UTC().Format(time.RFC3339Nano) == r.Timestamp && r.Schema == Schema && chainID.MatchString(r.ChainID) && digest.MatchString(r.PrevHash) &&
		name.MatchString(r.Host) && name.MatchString(r.Rule) && name.MatchString(r.Tool) &&
		(chainID.MatchString(r.ActionID) || digest.MatchString(r.ActionID)) && r.Redaction == "metadata-only.v1" &&
		((r.Event == "decision" && (r.Decision == "allow" || r.Decision == "deny" || r.Decision == "ask") && r.Outcome == "pending") ||
			(r.Event == "completion" && r.Decision == "none" && (r.Outcome == "success" || r.Outcome == "failure")))
}

// Verify checks every record and an optional previously retained checkpoint.
// Without a checkpoint an intact-prefix truncation or full rewrite is invisible.
func Verify(in io.Reader, expected *Checkpoint) (Checkpoint, error) {
	var tip Checkpoint
	br := bufio.NewReader(io.LimitReader(in, maxJournal+1))
	total := 0
	seen := expected == nil
	for {
		line, err := br.ReadBytes('\n')
		total += len(line)
		if total > maxJournal {
			return tip, errors.New("journal exceeds 64 MiB; archive explicitly")
		}
		if err == io.EOF && len(line) == 0 {
			break
		}
		if err != nil {
			return tip, errors.New("incomplete receipt line")
		}
		if len(line) > 8192 {
			return tip, errors.New("receipt line too long")
		}
		var r Record
		dec := json.NewDecoder(bytes.NewReader(line))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&r); err != nil {
			return tip, fmt.Errorf("invalid receipt at sequence %d", tip.Sequence+1)
		}
		canonical, err := Canonical(r, true)
		if err != nil || !bytes.Equal(append(canonical, '\n'), line) || !valid(r) {
			return tip, errors.New("noncanonical or invalid receipt")
		}
		prev := Genesis
		if tip.Sequence > 0 {
			prev = tip.Hash
		}
		hash, err := sum(r)
		if err != nil || !digest.MatchString(r.Hash) || hash != r.Hash || r.PrevHash != prev || r.Sequence != tip.Sequence+1 || (tip.Sequence > 0 && r.ChainID != tip.ChainID) {
			return tip, errors.New("receipt chain mismatch")
		}
		tip = Checkpoint{r.ChainID, r.Sequence, r.Hash}
		if expected != nil && tip.Sequence == expected.Sequence && tip == *expected {
			seen = true
		}
	}
	if !seen {
		return tip, errors.New("trusted checkpoint absent or changed (possible truncation)")
	}
	return tip, nil
}

// Append verifies and locks the same regular file before extending it. A write
// failure prevents the caller from allowing an action. Owner-controlled parent
// directories and OS permissions are part of the trust boundary.
func Append(path string, r Record) (Record, error) {
	f, err := openJournal(path)
	if err != nil {
		return r, err
	}
	defer f.Close()
	if err := lockJournal(f); err != nil {
		return r, err
	}
	defer unlockJournal(f)
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() || st.Mode().Perm()&0077 != 0 {
		return r, errors.New("journal must be a private regular file (0600)")
	}
	tip, err := Verify(f, nil)
	if err != nil {
		return r, err
	}
	r.Schema, r.Redaction = Schema, "metadata-only.v1"
	r.Timestamp = time.Now().UTC().Format(time.RFC3339Nano)
	r.Sequence, r.PrevHash, r.ChainID = tip.Sequence+1, tip.Hash, tip.ChainID
	if tip.Sequence == 0 {
		r.PrevHash = Genesis
		r.ChainID, err = ID()
		if err != nil {
			return r, err
		}
	}
	if !valid(r) {
		return r, errors.New("invalid receipt metadata")
	}
	r.Hash, err = sum(r)
	if err != nil {
		return r, err
	}
	data, err := Canonical(r, true)
	if err != nil {
		return r, err
	}
	if st.Size()+int64(len(data))+1 > maxJournal {
		return r, errors.New("journal capacity reached")
	}
	if _, err := f.Seek(0, io.SeekEnd); err != nil {
		return r, err
	}
	n, err := f.Write(append(data, '\n'))
	if err != nil || n != len(data)+1 {
		return r, errors.New("receipt write incomplete")
	}
	if err := f.Sync(); err != nil {
		return r, err
	}
	// Persist the directory entry as well, including first-time creation.
	parent, err := os.Open(filepath.Dir(path))
	if err != nil {
		return r, err
	}
	defer parent.Close()
	if err := parent.Sync(); err != nil {
		return r, err
	}
	return r, nil
}

// ActionID hashes host-provided correlation identifiers only. It is neither a
// digest of tool arguments nor proof of identity; it exposes session correlation.
func ActionID(session, toolUse string) (string, error) {
	if session == "" || toolUse == "" {
		return ID()
	}
	b, _ := json.Marshal([]string{session, toolUse})
	h := sha256.Sum256(b)
	return strings.ToLower(hex.EncodeToString(h[:])), nil
}
