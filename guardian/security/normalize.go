// Copyright 2025-2026 TakeInterest Inc.
// SPDX-License-Identifier: Apache-2.0

package security

import (
	"encoding/base64"
	"fmt"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"
)

// NormalizeInput applies a series of transformations to defeat evasion techniques
// that bypass regex-based detection. The original input is preserved for reporting;
// only the normalized copy is used for pattern matching.
//
// Pipeline order matters — each step feeds the next:
//  1. NFKC Unicode normalization (Cyrillic/Greek homoglyphs → ASCII)
//  2. Strip zero-width characters (U+200B, U+200C, U+200D, U+FEFF, U+2060, U+180E)
//  3. Normalize Unicode mathematical symbols (U+1D400–U+1D7FF → ASCII)
//  4. Strip HTML concealment (display:none, font-size:0, visibility:hidden)
//  5. Decode contextual Base64 (only near trigger words like "decode", "base64")
func NormalizeInput(s string) string {
	if len(s) == 0 {
		return s
	}

	// Step 1: NFKC normalization — maps compatibility characters to canonical forms.
	// Fullwidth Ａ → A, ligatures ﬁ → fi, superscripts, etc.
	s = norm.NFKC.String(s)

	// Step 1b: Map Unicode confusables (Cyrillic, Greek, etc.) to ASCII lookalikes.
	// NFKC doesn't handle cross-script homoglyphs since they're distinct canonical forms.
	s = mapConfusables(s)

	// Step 2: Strip zero-width and invisible formatting characters.
	s = stripZeroWidth(s)

	// Step 3: Normalize Unicode mathematical alphanumeric symbols.
	// U+1D400–U+1D7FF (math bold, italic, script, etc.) → ASCII equivalents.
	s = normalizeMathSymbols(s)

	// Step 4: Strip HTML concealment — elements designed to hide text from users
	// but still parseable by LLMs (e.g., display:none, font-size:0).
	s = stripHTMLConcealment(s)

	// Step 5: Contextual Base64 decoding — only decode when near trigger words.
	s = decodeContextualBase64(s)

	// Step 6: Decode percent-encoding so URL-encoded payloads (e.g.
	// "union%20all%20select") surface to the downstream SQLi/XSS patterns.
	// Conservative: only well-formed %XX sequences are decoded; malformed ones
	// are left intact so benign text containing a stray '%' is untouched.
	s = decodePercentEncoding(s)

	// Step 7: Expand IPv4-mapped IPv6 literals (e.g. "[::ffff:7f00:1]") to their
	// dotted-decimal form so the SSRF detector's loopback/private-range checks fire.
	s = expandMappedIPv6(s)

	return s
}

// confusableMap maps Unicode confusable characters (Cyrillic, Greek, etc.) to their
// ASCII lookalikes. NFKC normalization does NOT handle these because they are distinct
// canonical code points in their respective scripts.
var confusableMap = map[rune]rune{
	// Cyrillic → Latin
	'\u0410': 'A', // А
	'\u0412': 'B', // В
	'\u0421': 'C', // С
	'\u0415': 'E', // Е
	'\u041D': 'H', // Н
	'\u0406': 'I', // І (Ukrainian)
	'\u0408': 'J', // Ј (Serbian)
	'\u041A': 'K', // К
	'\u041C': 'M', // М
	'\u041E': 'O', // О
	'\u0420': 'P', // Р
	'\u0405': 'S', // Ѕ (Macedonian)
	'\u0422': 'T', // Т
	'\u0425': 'X', // Х
	'\u0430': 'a', // а
	'\u0435': 'e', // е
	'\u0456': 'i', // і (Ukrainian)
	'\u043E': 'o', // о
	'\u0440': 'p', // р
	'\u0441': 'c', // с
	'\u0443': 'y', // у
	'\u0445': 'x', // х
	'\u0455': 's', // ѕ (Macedonian)
	'\u0458': 'j', // ј (Serbian)
	'\u04BB': 'h', // һ (Bashkir)
	'\u0432': 'B', // в (note: lowercase Cyrillic в looks like Latin B in some fonts)
	'\u043A': 'k', // к (in many fonts indistinguishable)

	// Greek → Latin
	'\u0391': 'A', // Α
	'\u0392': 'B', // Β
	'\u0395': 'E', // Ε
	'\u0396': 'Z', // Ζ
	'\u0397': 'H', // Η
	'\u0399': 'I', // Ι
	'\u039A': 'K', // Κ
	'\u039C': 'M', // Μ
	'\u039D': 'N', // Ν
	'\u039F': 'O', // Ο
	'\u03A1': 'P', // Ρ
	'\u03A4': 'T', // Τ
	'\u03A5': 'Y', // Υ
	'\u03A7': 'X', // Χ
	'\u03B1': 'a', // α (debatable, but used in homoglyph attacks)
	'\u03BF': 'o', // ο
	'\u03B5': 'e', // ε (in some attack contexts)
	'\u03BA': 'k', // κ
	'\u03BD': 'v', // ν (looks like v)
	'\u03C1': 'p', // ρ
	'\u03C5': 'u', // υ

	// Armenian → Latin (common in attacks)
	'\u0555': 'O', // Օ
	'\u0585': 'o', // օ
	'\u0570': 'h', // հ
	'\u0578': 'n', // ո
	'\u057D': 's', // ս
	'\u0575': 'j', // յ
}

// mapConfusables replaces Unicode confusable characters with their ASCII equivalents.
func mapConfusables(s string) string {
	// Quick check: if all ASCII, nothing to do
	allASCII := true
	for i := 0; i < len(s); i++ {
		if s[i] > 127 {
			allASCII = false
			break
		}
	}
	if allASCII {
		return s
	}

	var b strings.Builder
	b.Grow(len(s))
	changed := false

	for _, r := range s {
		if mapped, ok := confusableMap[r]; ok {
			b.WriteRune(mapped)
			changed = true
		} else {
			b.WriteRune(r)
		}
	}

	if !changed {
		return s
	}
	return b.String()
}

// isZeroWidth returns true for Unicode zero-width and invisible formatting characters.
func isZeroWidth(r rune) bool {
	switch r {
	case '\u200B', // Zero Width Space
		'\u200C', // Zero Width Non-Joiner
		'\u200D', // Zero Width Joiner
		'\uFEFF', // Zero Width No-Break Space (BOM)
		'\u2060', // Word Joiner
		'\u180E', // Mongolian Vowel Separator
		'\u200E', // Left-to-Right Mark
		'\u200F', // Right-to-Left Mark
		'\u202A', // Left-to-Right Embedding
		'\u202B', // Right-to-Left Embedding
		'\u202C', // Pop Directional Formatting
		'\u202D', // Left-to-Right Override
		'\u202E', // Right-to-Left Override
		'\u2066', // Left-to-Right Isolate
		'\u2067', // Right-to-Left Isolate
		'\u2068', // First Strong Isolate
		'\u2069', // Pop Directional Isolate
		'\u00AD', // Soft Hyphen
		'\u061C', // Arabic Letter Mark
		'\u115F', // Hangul Choseong Filler
		'\u1160', // Hangul Jungseong Filler
		'\u3164', // Hangul Filler
		'\uFFA0': // Halfwidth Hangul Filler
		return true
	}
	// Unicode Tag characters (U+E0000\u2013U+E007F): invisible, used to smuggle ASCII
	// instructions past filters. Strip the entire block.
	if r >= 0xE0000 && r <= 0xE007F {
		return true
	}
	// Variation selectors (U+FE00\u2013U+FE0F, U+E0100\u2013U+E01EF) can also pad/hide text.
	if (r >= 0xFE00 && r <= 0xFE0F) || (r >= 0xE0100 && r <= 0xE01EF) {
		return true
	}
	return false
}

// stripZeroWidth removes all zero-width and invisible formatting characters.
func stripZeroWidth(s string) string {
	return strings.Map(func(r rune) rune {
		if isZeroWidth(r) {
			return -1 // drop
		}
		return r
	}, s)
}

// normalizeMathSymbols maps Unicode Mathematical Alphanumeric Symbols
// (U+1D400–U+1D7FF) back to their ASCII equivalents.
func normalizeMathSymbols(s string) string {
	if !containsMathSymbols(s) {
		return s
	}

	var b strings.Builder
	b.Grow(len(s))

	for _, r := range s {
		if mapped, ok := mapMathToASCII(r); ok {
			b.WriteRune(mapped)
		} else {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// containsMathSymbols is a quick check for whether the string might contain
// mathematical alphanumeric symbols (avoids allocation for common case).
func containsMathSymbols(s string) bool {
	for _, r := range s {
		if r >= 0x1D400 && r <= 0x1D7FF {
			return true
		}
	}
	return false
}

// mapMathToASCII maps a Unicode mathematical alphanumeric symbol to its ASCII equivalent.
// Covers: Bold, Italic, Bold Italic, Script, Bold Script, Fraktur, Bold Fraktur,
// Double-Struck, Sans-Serif, Sans-Serif Bold, Sans-Serif Italic,
// Sans-Serif Bold Italic, Monospace — for both uppercase and lowercase.
func mapMathToASCII(r rune) (rune, bool) {
	// Mathematical Bold Capital A–Z: U+1D400–U+1D419
	// Mathematical Bold Small a–z: U+1D41A–U+1D433
	// ... and so on for each style
	type mathRange struct {
		start rune
		base  rune
		count int
	}

	ranges := []mathRange{
		// Bold
		{0x1D400, 'A', 26}, {0x1D41A, 'a', 26},
		// Italic
		{0x1D434, 'A', 26}, {0x1D44E, 'a', 26},
		// Bold Italic
		{0x1D468, 'A', 26}, {0x1D482, 'a', 26},
		// Script
		{0x1D49C, 'A', 26}, {0x1D4B6, 'a', 26},
		// Bold Script
		{0x1D4D0, 'A', 26}, {0x1D4EA, 'a', 26},
		// Fraktur
		{0x1D504, 'A', 26}, {0x1D51E, 'a', 26},
		// Double-Struck
		{0x1D538, 'A', 26}, {0x1D552, 'a', 26},
		// Bold Fraktur
		{0x1D56C, 'A', 26}, {0x1D586, 'a', 26},
		// Sans-Serif
		{0x1D5A0, 'A', 26}, {0x1D5BA, 'a', 26},
		// Sans-Serif Bold
		{0x1D5D4, 'A', 26}, {0x1D5EE, 'a', 26},
		// Sans-Serif Italic
		{0x1D608, 'A', 26}, {0x1D622, 'a', 26},
		// Sans-Serif Bold Italic
		{0x1D63C, 'A', 26}, {0x1D656, 'a', 26},
		// Monospace
		{0x1D670, 'A', 26}, {0x1D68A, 'a', 26},
		// Bold digits 0–9
		{0x1D7CE, '0', 10},
		// Double-Struck digits
		{0x1D7D8, '0', 10},
		// Sans-Serif digits
		{0x1D7E2, '0', 10},
		// Sans-Serif Bold digits
		{0x1D7EC, '0', 10},
		// Monospace digits
		{0x1D7F6, '0', 10},
	}

	for _, mr := range ranges {
		if r >= mr.start && r < mr.start+rune(mr.count) {
			return mr.base + (r - mr.start), true
		}
	}
	return r, false
}

// HTML concealment patterns — elements that hide text visually but not from LLM parsing.
var htmlConcealmentPatterns = []*regexp.Regexp{
	// Tags with display:none, visibility:hidden, font-size:0, opacity:0
	regexp.MustCompile(`(?i)<[^>]+style\s*=\s*"[^"]*(?:display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0|opacity\s*:\s*0)[^"]*"[^>]*>.*?</[^>]+>`),
	regexp.MustCompile(`(?i)<[^>]+style\s*=\s*'[^']*(?:display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0|opacity\s*:\s*0)[^']*'[^>]*>.*?</[^>]+>`),
	// White-on-white text (color:white on white background, or color:#fff/#ffffff)
	regexp.MustCompile(`(?i)<[^>]+style\s*=\s*"[^"]*color\s*:\s*(?:white|#fff(?:fff)?|rgb\s*\(\s*255\s*,\s*255\s*,\s*255\s*\))[^"]*"[^>]*>(.*?)</[^>]+>`),
	// Zero-height/width elements
	regexp.MustCompile(`(?i)<[^>]+style\s*=\s*"[^"]*(?:height\s*:\s*0|width\s*:\s*0|overflow\s*:\s*hidden)[^"]*"[^>]*>.*?</[^>]+>`),
	// Hidden input fields with suspicious content
	regexp.MustCompile(`(?i)<input[^>]+type\s*=\s*"hidden"[^>]*value\s*=\s*"([^"]*)"[^>]*/?\s*>`),
	// HTML comments (can contain injection payloads)
	regexp.MustCompile(`<!--[\s\S]*?-->`),
}

// stripHTMLConcealment removes HTML elements designed to hide text.
func stripHTMLConcealment(s string) string {
	if !strings.Contains(s, "<") {
		return s
	}

	for _, pat := range htmlConcealmentPatterns {
		s = pat.ReplaceAllString(s, " ")
	}

	// Collapse multiple spaces to single
	spaceCollapse := regexp.MustCompile(`\s{2,}`)
	s = spaceCollapse.ReplaceAllString(s, " ")

	return strings.TrimSpace(s)
}

// base64TriggerPattern matches context words adjacent to Base64 candidates.
var base64TriggerPattern = regexp.MustCompile(`(?i)(?:decode|base64|execute\s+encoded|eval\s+encoded|run\s+encoded)\s*[:=]?\s*`)

// base64CandidatePattern matches potential Base64 strings (40+ chars, valid charset, optional padding).
var base64CandidatePattern = regexp.MustCompile(`[A-Za-z0-9+/]{40,}={0,2}`)

// decodeContextualBase64 decodes Base64 strings only when they appear near trigger words.
func decodeContextualBase64(s string) string {
	if !base64TriggerPattern.MatchString(s) {
		return s
	}

	triggerLocs := base64TriggerPattern.FindAllStringIndex(s, -1)
	candidates := base64CandidatePattern.FindAllStringIndex(s, -1)

	if len(candidates) == 0 {
		return s
	}

	var result strings.Builder
	result.Grow(len(s) * 2) // may grow if decoded content is longer

	lastEnd := 0

	for _, cand := range candidates {
		// Check if any trigger word is within 100 chars before this candidate
		nearTrigger := false
		for _, trig := range triggerLocs {
			// Trigger ends before candidate starts, and is within 100 chars
			if trig[1] <= cand[0] && cand[0]-trig[1] < 100 {
				nearTrigger = true
				break
			}
		}

		if !nearTrigger {
			continue
		}

		b64str := s[cand[0]:cand[1]]
		decoded, err := base64.StdEncoding.DecodeString(b64str)
		if err != nil {
			// Try RawStdEncoding (no padding)
			decoded, err = base64.RawStdEncoding.DecodeString(b64str)
			if err != nil {
				continue
			}
		}

		// Only replace if decoded content is valid UTF-8 and printable
		if !utf8.Valid(decoded) {
			continue
		}
		decodedStr := string(decoded)
		if !isPrintableUTF8(decodedStr) {
			continue
		}

		result.WriteString(s[lastEnd:cand[0]])
		result.WriteString(decodedStr)
		lastEnd = cand[1]
	}

	if lastEnd == 0 {
		return s // no replacements made
	}

	result.WriteString(s[lastEnd:])
	return result.String()
}

// decodePercentEncoding URL-decodes well-formed %XX sequences so URL-encoded
// payloads (e.g. "union%20all%20select") surface to the downstream SQLi/XSS
// patterns. It decodes at the BYTE level (per RFC 3986), then keeps the result
// only when it is valid printable UTF-8.
//
// The UTF-8 guard is load-bearing for safety, not cosmetics: byte-oriented
// evasions like the overlong-slash "%c0%af" decode to non-UTF-8 bytes, so they
// are deliberately LEFT in their encoded form — that is the exact shape the
// path-traversal detector already matches. Decoding them would erase the signal.
func decodePercentEncoding(s string) string {
	if !strings.Contains(s, "%") {
		return s
	}
	decoded, err := url.PathUnescape(s) // PathUnescape leaves '+' untouched
	if err != nil || decoded == s {
		return s
	}
	if !utf8.ValidString(decoded) || !isPrintableUTF8(decoded) {
		return s // refuse a decode that yields non-printable/non-UTF-8 bytes
	}
	return decoded
}

// mappedIPv6Pattern matches an IPv4-mapped IPv6 literal of the form
// ::ffff:HHHH:HHHH (optionally inside brackets), e.g. "[::ffff:7f00:1]".
var mappedIPv6Pattern = regexp.MustCompile(`(?i)::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})`)

// expandMappedIPv6 rewrites IPv4-mapped IPv6 literals to dotted-decimal so the
// SSRF detector's existing IPv4 loopback/private-range checks apply. The original
// (unexpanded) form is a known SSRF evasion against IPv4-only allow/deny lists.
func expandMappedIPv6(s string) string {
	if !strings.Contains(s, "::ffff:") && !strings.Contains(s, "::FFFF:") {
		return s
	}
	return mappedIPv6Pattern.ReplaceAllStringFunc(s, func(m string) string {
		g := mappedIPv6Pattern.FindStringSubmatch(m)
		if len(g) != 3 {
			return m
		}
		hi, err1 := strconv.ParseUint(g[1], 16, 16)
		lo, err2 := strconv.ParseUint(g[2], 16, 16)
		if err1 != nil || err2 != nil {
			return m
		}
		return fmt.Sprintf("%d.%d.%d.%d", (hi>>8)&0xff, hi&0xff, (lo>>8)&0xff, lo&0xff)
	})
}

// isPrintableUTF8 checks that all runes are printable (no control chars except space/newline/tab).
func isPrintableUTF8(s string) bool {
	for _, r := range s {
		if r == '\n' || r == '\r' || r == '\t' || r == ' ' {
			continue
		}
		if !unicode.IsPrint(r) {
			return false
		}
	}
	return true
}
