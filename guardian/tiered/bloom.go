// Copyright 2025-2026 TakeInterest Inc.
// SPDX-License-Identifier: Apache-2.0

package tiered

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"sync"
)

const bloomVersion = uint8(1)

// BloomFilter is a space-efficient probabilistic set.
// It guarantees zero false negatives: if an item was inserted, Lookup always returns true.
// It allows a configurable false positive rate (items not inserted may return true).
//
// Concurrency: Insert and Encode hold a write lock. Lookup, Len, and FPRate hold a read
// lock. Cap returns an immutable field with no lock. The unexported hashIndices method
// reads m and k which are also immutable after construction — safe without a lock.
type BloomFilter struct {
	mu   sync.RWMutex
	bits []uint64 // m bits stored as ceil(m/64) uint64 words
	m    uint64   // total bits (immutable after construction)
	k    uint8    // number of hash functions (immutable after construction)
	n    uint64   // number of items inserted
}

// NewBloomFilter creates a Bloom filter sized for expectedN items at fpRate false
// positive probability. Returns an error if expectedN <= 0 or fpRate is not in (0, 1).
func NewBloomFilter(expectedN int, fpRate float64) (*BloomFilter, error) {
	if expectedN <= 0 {
		return nil, errors.New("expected entries must be positive")
	}
	if fpRate <= 0 || fpRate >= 1 {
		return nil, errors.New("false positive rate must be in (0, 1)")
	}

	n := float64(expectedN)
	ln2 := math.Log(2)

	// Optimal bit count: m = ceil(-n * ln(p) / ln(2)²)
	m := math.Ceil(-n * math.Log(fpRate) / (ln2 * ln2))

	// Optimal hash function count: k = round((m/n) * ln(2)), clamped to [1, 255]
	k := math.Round((m / n) * ln2)
	if k < 1 {
		k = 1
	}
	if k > 255 {
		k = 255
	}

	mBits := uint64(m)
	words := (mBits + 63) / 64 // ceil(m / 64)

	return &BloomFilter{
		bits: make([]uint64, words),
		m:    mBits,
		k:    uint8(k),
	}, nil
}

// Insert adds data to the filter. nil is treated as an empty byte slice.
// Thread-safe.
func (bf *BloomFilter) Insert(data []byte) {
	if data == nil {
		data = []byte{}
	}
	indices := bf.hashIndices(data)
	bf.mu.Lock()
	for _, idx := range indices {
		bf.bits[idx/64] |= 1 << (idx % 64)
	}
	bf.n++
	bf.mu.Unlock()
}

// Lookup reports whether data may be in the filter. nil is treated as an empty byte slice.
// Returns true if the item was possibly inserted (may be a false positive).
// Returns false if the item was definitely NOT inserted (no false negatives).
// Thread-safe.
func (bf *BloomFilter) Lookup(data []byte) bool {
	if data == nil {
		data = []byte{}
	}
	indices := bf.hashIndices(data)
	bf.mu.RLock()
	defer bf.mu.RUnlock()
	for _, idx := range indices {
		if bf.bits[idx/64]&(1<<(idx%64)) == 0 {
			return false
		}
	}
	return true
}

// hashIndices computes k bit positions from data using SHA-256 double hashing
// (Kirsch-Mitzenmacher optimization). One SHA-256 call yields k independent positions:
//
//	h1 = first 8 bytes of digest as uint64
//	h2 = next 8 bytes of digest as uint64
//	position[i] = (h1 + i*h2) % m   for i in 0..k-1
//
// uint64 arithmetic wraps naturally, which is safe and correct here.
func (bf *BloomFilter) hashIndices(data []byte) []uint64 {
	digest := sha256.Sum256(data)
	h1 := binary.BigEndian.Uint64(digest[0:8])
	h2 := binary.BigEndian.Uint64(digest[8:16])
	indices := make([]uint64, bf.k)
	for i := uint64(0); i < uint64(bf.k); i++ {
		indices[i] = (h1 + i*h2) % bf.m
	}
	return indices
}

// Encode serializes the filter to w in binary format (BigEndian).
// Wire format: [version:uint8][m:uint64][k:uint8][n:uint64][bits:[]uint64]
// Thread-safe.
func (bf *BloomFilter) Encode(w io.Writer) error {
	bf.mu.RLock()
	defer bf.mu.RUnlock()

	if err := binary.Write(w, binary.BigEndian, bloomVersion); err != nil {
		return fmt.Errorf("bloom: write version: %w", err)
	}
	if err := binary.Write(w, binary.BigEndian, bf.m); err != nil {
		return fmt.Errorf("bloom: write m: %w", err)
	}
	if err := binary.Write(w, binary.BigEndian, bf.k); err != nil {
		return fmt.Errorf("bloom: write k: %w", err)
	}
	if err := binary.Write(w, binary.BigEndian, bf.n); err != nil {
		return fmt.Errorf("bloom: write n: %w", err)
	}
	for _, word := range bf.bits {
		if err := binary.Write(w, binary.BigEndian, word); err != nil {
			return fmt.Errorf("bloom: write bits: %w", err)
		}
	}
	return nil
}

// Decode deserializes a filter from r. Returns an error if the data is corrupted,
// truncated, or uses an unsupported version.
func Decode(r io.Reader) (*BloomFilter, error) {
	var version uint8
	if err := binary.Read(r, binary.BigEndian, &version); err != nil {
		return nil, fmt.Errorf("bloom: read version: %w", err)
	}
	if version != bloomVersion {
		return nil, fmt.Errorf("bloom: unsupported version %d", version)
	}

	var m uint64
	if err := binary.Read(r, binary.BigEndian, &m); err != nil {
		return nil, fmt.Errorf("bloom: read m: %w", err)
	}

	var k uint8
	if err := binary.Read(r, binary.BigEndian, &k); err != nil {
		return nil, fmt.Errorf("bloom: read k: %w", err)
	}

	var n uint64
	if err := binary.Read(r, binary.BigEndian, &n); err != nil {
		return nil, fmt.Errorf("bloom: read n: %w", err)
	}

	words := (m + 63) / 64
	bits := make([]uint64, words)
	if err := binary.Read(r, binary.BigEndian, bits); err != nil {
		return nil, fmt.Errorf("bloom: read bits: %w", err)
	}

	return &BloomFilter{
		bits: bits,
		m:    m,
		k:    k,
		n:    n,
	}, nil
}

// Len returns the number of items inserted into the filter.
// Thread-safe.
func (bf *BloomFilter) Len() uint64 {
	bf.mu.RLock()
	defer bf.mu.RUnlock()
	return bf.n
}

// Cap returns the total number of bits allocated in the filter.
// This value is immutable after construction — no lock is needed.
func (bf *BloomFilter) Cap() uint64 {
	return bf.m
}

// FPRate returns the theoretical false positive rate at the current fill level.
// Formula: (1 - e^(-k*n/m))^k
// Returns 0 if no items have been inserted.
// Thread-safe.
func (bf *BloomFilter) FPRate() float64 {
	bf.mu.RLock()
	n := bf.n
	m := bf.m
	k := bf.k
	bf.mu.RUnlock()

	if n == 0 || m == 0 {
		return 0
	}
	exponent := -float64(k) * float64(n) / float64(m)
	return math.Pow(1-math.Exp(exponent), float64(k))
}
