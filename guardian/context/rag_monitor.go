// Copyright 2025-2026 TakeInterest Inc.
// SPDX-License-Identifier: Apache-2.0

package context

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"sync"
	"time"
)

// DocumentSource identifies the provenance of a retrieved document.
type DocumentSource string

const (
	SourceVectorStore DocumentSource = "vector_store"
	SourceFileSystem  DocumentSource = "filesystem"
	SourceWebCrawl    DocumentSource = "web_crawl"
	SourceAPI         DocumentSource = "api"
	SourceUserUpload  DocumentSource = "user_upload"
	SourceUnknown     DocumentSource = "unknown"
)

// RetrievedDocument represents a document fetched from a RAG store.
type RetrievedDocument struct {
	ID          string            `json:"id"`
	Content     string            `json:"content"`
	Source      DocumentSource    `json:"source"`
	SourceRef   string            `json:"source_ref,omitempty"` // URI, file path, or collection name
	Metadata    map[string]string `json:"metadata,omitempty"`
	RetrievedAt time.Time         `json:"retrieved_at"`
}

// RAGFinding represents a poisoning detection in a retrieved document.
type RAGFinding struct {
	DocumentID  string             `json:"document_id"`
	PatternName string             `json:"pattern_name"`
	Category    RAGPatternCategory `json:"category"`
	Severity    float64            `json:"severity"`
	Confidence  float64            `json:"confidence"`
	MatchedText string             `json:"matched_text"`
	Source      DocumentSource     `json:"source"`
	SourceRef   string             `json:"source_ref,omitempty"`
}

// RAGScanResult aggregates findings from scanning a set of retrieved documents.
type RAGScanResult struct {
	Findings     []RAGFinding  `json:"findings"`
	TotalDocs    int           `json:"total_docs"`
	PoisonedDocs int           `json:"poisoned_docs"`
	SkippedDocs  int           `json:"skipped_docs,omitempty"`
	TamperedDocs int           `json:"tampered_docs"`
	ScanDuration time.Duration `json:"scan_duration_ns"`
}

// IsPoisoned conservatively flags detected poisoning or an incomplete scan.
func (r *RAGScanResult) IsPoisoned() bool {
	return len(r.Findings) > 0
}

// MaxSeverity returns the highest severity across all findings.
func (r *RAGScanResult) MaxSeverity() float64 {
	max := 0.0
	for _, f := range r.Findings {
		if f.Severity > max {
			max = f.Severity
		}
	}
	return max
}

// RAGMonitor scans retrieved documents for poisoning patterns and
// tracks document integrity across retrieval sessions.
type RAGMonitor struct {
	// MaxFindingsPerDoc limits noise from a single poisoned document.
	MaxFindingsPerDoc int

	// MaxDocSizeBytes bounds scanning (default: 1MB). Oversized documents
	// produce an explicit incomplete-scan finding, never a clean result.
	MaxDocSizeBytes int

	// mu protects the document hash cache.
	mu        sync.RWMutex
	docHashes map[string]string // docID → SHA-256 of last seen content
}

// NewRAGMonitor creates a RAG monitor with sensible defaults.
func NewRAGMonitor() *RAGMonitor {
	return &RAGMonitor{
		MaxFindingsPerDoc: 5,
		MaxDocSizeBytes:   1024 * 1024,
		docHashes:         make(map[string]string),
	}
}

// ScanDocuments analyzes a batch of retrieved documents for poisoning patterns.
// It also detects content changes since the last time each document was seen.
func (rm *RAGMonitor) ScanDocuments(docs []RetrievedDocument) *RAGScanResult {
	start := time.Now()
	result := &RAGScanResult{
		TotalDocs: len(docs),
	}

	poisonedSet := make(map[string]bool)

	for i := range docs {
		doc := &docs[i]

		// Preserve the resource bound without silently declaring unsafe input clean.
		if len(doc.Content) > rm.MaxDocSizeBytes {
			result.SkippedDocs++
			result.Findings = append(result.Findings, incompleteRAGFinding(doc))
			continue
		}

		// Check for content tampering (document changed since last seen).
		if rm.detectTampering(doc) {
			result.TamperedDocs++
		}

		// Scan for poisoning patterns.
		findings := rm.scanDocument(doc)
		if len(findings) > 0 {
			poisonedSet[doc.ID] = true
			result.Findings = append(result.Findings, findings...)
		}
	}

	result.PoisonedDocs = len(poisonedSet)
	result.ScanDuration = time.Since(start)
	return result
}

// ScanSingleDocument analyzes one document and returns findings.
func (rm *RAGMonitor) ScanSingleDocument(doc *RetrievedDocument) []RAGFinding {
	if len(doc.Content) > rm.MaxDocSizeBytes {
		return []RAGFinding{incompleteRAGFinding(doc)}
	}
	return rm.scanDocument(doc)
}

// IsComplete reports whether every supplied document was scanned.
func (r *RAGScanResult) IsComplete() bool { return r.SkippedDocs == 0 }

func incompleteRAGFinding(doc *RetrievedDocument) RAGFinding {
	return RAGFinding{DocumentID: doc.ID, PatternName: "scan_incomplete_size_limit",
		Category: "scan_limit", Severity: 1, Confidence: 1, Source: doc.Source, SourceRef: doc.SourceRef}
}

// CheckTampering returns true if the document content has changed
// since the last time it was scanned. First-time documents return false.
func (rm *RAGMonitor) CheckTampering(doc *RetrievedDocument) bool {
	return rm.detectTampering(doc)
}

// DocumentHashCount returns the number of tracked document hashes.
func (rm *RAGMonitor) DocumentHashCount() int {
	rm.mu.RLock()
	defer rm.mu.RUnlock()
	return len(rm.docHashes)
}

// ClearHashes resets the document hash cache.
func (rm *RAGMonitor) ClearHashes() {
	rm.mu.Lock()
	defer rm.mu.Unlock()
	rm.docHashes = make(map[string]string)
}

// scanDocument scans a single document against all RAG poisoning patterns.
func (rm *RAGMonitor) scanDocument(doc *RetrievedDocument) []RAGFinding {
	var findings []RAGFinding
	content := doc.Content

	for _, p := range ragPoisonPatterns {
		if len(findings) >= rm.MaxFindingsPerDoc {
			break
		}

		loc := p.Pattern.FindStringIndex(content)
		if loc == nil {
			continue
		}

		// Extract matched text (truncate to 120 chars for readability).
		matched := content[loc[0]:loc[1]]
		if len(matched) > 120 {
			matched = matched[:120] + "..."
		}

		findings = append(findings, RAGFinding{
			DocumentID:  doc.ID,
			PatternName: p.Name,
			Category:    p.Category,
			Severity:    p.Severity,
			Confidence:  p.Confidence,
			MatchedText: matched,
			Source:      doc.Source,
			SourceRef:   doc.SourceRef,
		})
	}

	return findings
}

// detectTampering checks if a document's content has changed since last seen.
// Updates the hash cache. Returns false for first-time documents.
func (rm *RAGMonitor) detectTampering(doc *RetrievedDocument) bool {
	hash := hashContent(doc.Content)

	rm.mu.Lock()
	defer rm.mu.Unlock()

	prev, exists := rm.docHashes[doc.ID]
	rm.docHashes[doc.ID] = hash

	if !exists {
		return false // First time seeing this document.
	}
	return prev != hash
}

// hashContent returns the SHA-256 hex digest of content.
func hashContent(content string) string {
	h := sha256.Sum256([]byte(content))
	return hex.EncodeToString(h[:])
}

// CategorizeFindings groups findings by category and returns counts.
func CategorizeFindings(findings []RAGFinding) map[RAGPatternCategory]int {
	counts := make(map[RAGPatternCategory]int)
	for _, f := range findings {
		counts[f.Category]++
	}
	return counts
}

// HighSeverityFindings filters findings above the given severity threshold.
func HighSeverityFindings(findings []RAGFinding, threshold float64) []RAGFinding {
	var result []RAGFinding
	for _, f := range findings {
		if f.Severity >= threshold {
			result = append(result, f)
		}
	}
	return result
}

// SummarizeResult returns a human-readable summary of RAG scan results.
func SummarizeResult(r *RAGScanResult) string {
	if !r.IsPoisoned() && r.TamperedDocs == 0 && r.IsComplete() {
		return "RAG scan clean: no poisoning detected"
	}

	var b strings.Builder
	b.WriteString("RAG scan alert: ")
	if !r.IsComplete() {
		b.WriteString("incomplete: " + intToStr(r.SkippedDocs) + " doc(s) exceed size limit; ")
	}

	if r.PoisonedDocs > 0 {
		b.WriteString(strings.Join([]string{
			intToStr(r.PoisonedDocs), " poisoned doc(s), ",
			intToStr(len(r.Findings)), " finding(s)",
		}, ""))
	}
	if r.TamperedDocs > 0 {
		if r.PoisonedDocs > 0 {
			b.WriteString("; ")
		}
		b.WriteString(intToStr(r.TamperedDocs))
		b.WriteString(" tampered doc(s)")
	}
	return b.String()
}

// intToStr converts an int to string without importing strconv.
func intToStr(n int) string {
	if n == 0 {
		return "0"
	}
	if n < 0 {
		return "-" + intToStr(-n)
	}
	digits := make([]byte, 0, 4)
	for n > 0 {
		digits = append(digits, byte('0'+n%10))
		n /= 10
	}
	// Reverse.
	for i, j := 0, len(digits)-1; i < j; i, j = i+1, j-1 {
		digits[i], digits[j] = digits[j], digits[i]
	}
	return string(digits)
}
