// Copyright 2025-2026 TakeInterest Inc.
// SPDX-License-Identifier: Apache-2.0

// Package security provides HTTP header injection detection for AI agents
// that construct or forward HTTP requests.
package security

import (
	"regexp"
	"strings"
)

// HeaderInjectionCategory categorizes HTTP header injection attack types.
type HeaderInjectionCategory string

const (
	HeaderCategoryCRLF           HeaderInjectionCategory = "crlf_injection"
	HeaderCategoryHostHeader     HeaderInjectionCategory = "host_header"
	HeaderCategoryRequestSmuggle HeaderInjectionCategory = "request_smuggling"
	HeaderCategoryHeaderValue    HeaderInjectionCategory = "header_value_injection"
	HeaderCategoryResponseSplit  HeaderInjectionCategory = "response_splitting"
	HeaderCategoryCachePoisoning HeaderInjectionCategory = "cache_poisoning"
	HeaderCategoryHTTP2          HeaderInjectionCategory = "http2"
	HeaderCategorySecBypass      HeaderInjectionCategory = "security_header_bypass"
	HeaderCategoryAdvSmuggling   HeaderInjectionCategory = "advanced_smuggling"
)

// HeaderInjectionPattern represents an HTTP header injection detection pattern.
type HeaderInjectionPattern struct {
	Pattern    *regexp.Regexp
	Category   HeaderInjectionCategory
	Severity   float64 // 0.0-1.0
	Confidence float64 // 0.0-1.0
	Name       string
	Example    string
}

// HeaderInjectionPatterns contains comprehensive HTTP header injection detection.
// Total: 35 patterns across 5 categories.
var HeaderInjectionPatterns = []HeaderInjectionPattern{
	// === CRLF Injection (10 patterns) ===
	{regexp.MustCompile(`\r\n`), HeaderCategoryCRLF, 0.90, 0.85, "crlf_literal", "header: value\r\ninjected: header"},
	{regexp.MustCompile(`(?i)%0d%0a`), HeaderCategoryCRLF, 0.95, 0.90, "crlf_url_encoded", `header%0d%0ainjected:%20value`},
	{regexp.MustCompile(`(?i)%0a`), HeaderCategoryCRLF, 0.85, 0.80, "lf_url_encoded", `header%0ainjected: value`},
	{regexp.MustCompile(`(?i)%0d`), HeaderCategoryCRLF, 0.85, 0.80, "cr_url_encoded", `header%0dinjected: value`},
	{regexp.MustCompile(`(?i)%e5%98%8a%e5%98%8d`), HeaderCategoryCRLF, 0.95, 0.90, "utf8_crlf_bypass", `%e5%98%8a%e5%98%8dinjected: value`},
	{regexp.MustCompile(`(?i)\\r\\n`), HeaderCategoryCRLF, 0.80, 0.75, "escaped_crlf", `header\\r\\ninjected: value`},
	{regexp.MustCompile(`(?i)%5cr%5cn`), HeaderCategoryCRLF, 0.85, 0.80, "double_encoded_crlf", `%5cr%5cninjected: value`},
	{regexp.MustCompile(`\x0d\x0a`), HeaderCategoryCRLF, 0.90, 0.90, "raw_crlf_bytes", "value\x0d\x0ainjected: header"},
	{regexp.MustCompile(`(?i)%c0%8d%c0%8a`), HeaderCategoryCRLF, 0.95, 0.90, "overlong_utf8_crlf", `%c0%8d%c0%8ainjected: value`},
	{regexp.MustCompile(`(?i)(?:%0d%0a|%0a|%0d){2,}`), HeaderCategoryCRLF, 0.95, 0.90, "multi_crlf_body_inject", `%0d%0a%0d%0a<html>injected</html>`},

	// === Host Header Attacks (7 patterns) ===
	{regexp.MustCompile(`(?i)(?:^|\s)Host:\s*[^,\s]+,\s*[^,\s]+`), HeaderCategoryHostHeader, 0.90, 0.85, "duplicate_host_header", `Host: legitimate.com, evil.com`},
	{regexp.MustCompile(`(?i)X-Forwarded-Host:\s*`), HeaderCategoryHostHeader, 0.75, 0.70, "x_forwarded_host", `X-Forwarded-Host: evil.com`},
	{regexp.MustCompile(`(?i)X-Original-URL:\s*`), HeaderCategoryHostHeader, 0.80, 0.75, "x_original_url", `X-Original-URL: /admin`},
	{regexp.MustCompile(`(?i)X-Rewrite-URL:\s*`), HeaderCategoryHostHeader, 0.80, 0.75, "x_rewrite_url", `X-Rewrite-URL: /admin`},
	{regexp.MustCompile(`(?i)X-Forwarded-For:\s*127\.0\.0\.1`), HeaderCategoryHostHeader, 0.85, 0.80, "xff_loopback_spoof", `X-Forwarded-For: 127.0.0.1`},
	{regexp.MustCompile(`(?i)X-Real-IP:\s*127\.0\.0\.1`), HeaderCategoryHostHeader, 0.85, 0.80, "xrealip_loopback_spoof", `X-Real-IP: 127.0.0.1`},
	{regexp.MustCompile(`(?i)X-Forwarded-For:\s*(?:10\.\d|172\.(?:1[6-9]|2\d|3[01])\.\d|192\.168\.)`), HeaderCategoryHostHeader, 0.80, 0.75, "xff_internal_spoof", `X-Forwarded-For: 10.0.0.1`},

	// === Request Smuggling Indicators (7 patterns) ===
	{regexp.MustCompile(`(?i)Transfer-Encoding:\s*chunked.*Content-Length:`), HeaderCategoryRequestSmuggle, 0.95, 0.90, "cl_te_smuggling", `Transfer-Encoding: chunked\r\nContent-Length: 0`},
	{regexp.MustCompile(`(?i)Content-Length:.*Transfer-Encoding:\s*chunked`), HeaderCategoryRequestSmuggle, 0.95, 0.90, "te_cl_smuggling", `Content-Length: 42\r\nTransfer-Encoding: chunked`},
	{regexp.MustCompile(`(?i)Transfer-Encoding:\s*(?:chunked\s*,\s*identity|identity\s*,\s*chunked)`), HeaderCategoryRequestSmuggle, 0.95, 0.90, "te_obfuscation", `Transfer-Encoding: chunked, identity`},
	{regexp.MustCompile(`(?i)Transfer-Encoding\s*:\s*chunked`), HeaderCategoryRequestSmuggle, 0.80, 0.70, "te_space_before_colon", `Transfer-Encoding : chunked`},
	{regexp.MustCompile(`(?i)Transfer-Encoding:\s*\tchunked`), HeaderCategoryRequestSmuggle, 0.85, 0.80, "te_tab_obfuscation", "Transfer-Encoding:\tchunked"},
	{regexp.MustCompile(`(?i)Content-Length:\s*\d+\s*Content-Length:\s*\d+`), HeaderCategoryRequestSmuggle, 0.95, 0.90, "duplicate_content_length", `Content-Length: 0\r\nContent-Length: 42`},
	{regexp.MustCompile(`0\r\n\r\n`), HeaderCategoryRequestSmuggle, 0.70, 0.65, "chunked_terminator", "0\r\n\r\n"},

	// === Header Value Injection (4 patterns) ===
	{regexp.MustCompile(`(?i)(?:Authorization|Cookie|Set-Cookie):\s*.*?[;\s](?:admin|root|superuser)\b`), HeaderCategoryHeaderValue, 0.85, 0.75, "auth_header_privilege", `Cookie: role=admin`},
	{regexp.MustCompile(`(?i)Set-Cookie:.*?(?:;\s*domain=\.[^;]+){2,}`), HeaderCategoryHeaderValue, 0.85, 0.80, "cookie_domain_injection", `Set-Cookie: a=b; domain=.evil.com; domain=.victim.com`},
	{regexp.MustCompile(`(?i)(?:Authorization:\s*Bearer\s+)(?:eyJ[A-Za-z0-9_-]*\.){2}[A-Za-z0-9_-]*`), HeaderCategoryHeaderValue, 0.70, 0.65, "jwt_in_header", `Authorization: Bearer eyJhbGciOiJub25lIn0...`},
	{regexp.MustCompile(`(?i)Proxy-Authorization:\s*Basic\s+`), HeaderCategoryHeaderValue, 0.80, 0.75, "proxy_auth_injection", `Proxy-Authorization: Basic YWRtaW46YWRtaW4=`},

	// === Response Splitting (7 patterns) ===
	{regexp.MustCompile(`(?i)HTTP/[12]\.[01]\s+200\s+OK`), HeaderCategoryResponseSplit, 0.85, 0.80, "injected_response_line", `HTTP/1.1 200 OK`},
	{regexp.MustCompile(`(?i)Content-Type:\s*text/html.*?<(?:script|html|body)`), HeaderCategoryResponseSplit, 0.90, 0.85, "injected_html_response", `Content-Type: text/html\r\n\r\n<script>alert(1)</script>`},
	{regexp.MustCompile(`(?i)Location:\s*(?:https?://|//)[^\s]+`), HeaderCategoryResponseSplit, 0.75, 0.70, "injected_redirect", `Location: http://evil.com/`},
	{regexp.MustCompile(`(?i)Set-Cookie:\s*[^=]+=.*?(?:;\s*(?:Secure|HttpOnly|SameSite))*\s*$`), HeaderCategoryResponseSplit, 0.70, 0.65, "injected_cookie", `Set-Cookie: session=evil`},
	{regexp.MustCompile(`(?i)Access-Control-Allow-Origin:\s*\*`), HeaderCategoryResponseSplit, 0.75, 0.70, "injected_cors_wildcard", `Access-Control-Allow-Origin: *`},
	{regexp.MustCompile(`(?i)X-Frame-Options:\s*ALLOWALL`), HeaderCategoryResponseSplit, 0.80, 0.75, "injected_frame_bypass", `X-Frame-Options: ALLOWALL`},
	{regexp.MustCompile(`(?i)Content-Security-Policy:\s*(?:default-src\s+'none'|.*?unsafe-eval.*?unsafe-inline)`), HeaderCategoryResponseSplit, 0.75, 0.70, "injected_csp_bypass", `Content-Security-Policy: default-src 'none'`},

	// === Cache Poisoning (12 patterns) ===
	{regexp.MustCompile(`(?i)X-Forwarded-Scheme:\s*`), HeaderCategoryCachePoisoning, 0.80, 0.75, "x_forwarded_scheme", `X-Forwarded-Scheme: nothttps`},
	{regexp.MustCompile(`(?i)X-Forwarded-Proto:\s*http\b`), HeaderCategoryCachePoisoning, 0.80, 0.75, "x_forwarded_proto_http", `X-Forwarded-Proto: http`},
	{regexp.MustCompile(`(?i)X-Forwarded-Port:\s*`), HeaderCategoryCachePoisoning, 0.75, 0.70, "x_forwarded_port", `X-Forwarded-Port: 8080`},
	{regexp.MustCompile(`(?i)X-HTTP-Method-Override:\s*`), HeaderCategoryCachePoisoning, 0.85, 0.80, "x_http_method_override", `X-HTTP-Method-Override: PUT`},
	{regexp.MustCompile(`(?i)X-Method-Override:\s*`), HeaderCategoryCachePoisoning, 0.85, 0.80, "x_method_override", `X-Method-Override: DELETE`},
	{regexp.MustCompile(`(?i)X-Original-Method:\s*`), HeaderCategoryCachePoisoning, 0.85, 0.80, "x_original_method", `X-Original-Method: PATCH`},
	{regexp.MustCompile(`(?i)Cache-Control:.*public\b`), HeaderCategoryCachePoisoning, 0.70, 0.65, "cache_control_public", `Cache-Control: public, max-age=3600`},
	{regexp.MustCompile(`(?i)Surrogate-Control:\s*`), HeaderCategoryCachePoisoning, 0.80, 0.75, "surrogate_control", `Surrogate-Control: no-store`},
	{regexp.MustCompile(`(?i)CDN-Cache-Control:\s*`), HeaderCategoryCachePoisoning, 0.80, 0.75, "cdn_cache_control", `CDN-Cache-Control: max-age=60`},
	{regexp.MustCompile(`(?i)X-Cache-Key:\s*`), HeaderCategoryCachePoisoning, 0.80, 0.75, "x_cache_key", `X-Cache-Key: /page`},
	{regexp.MustCompile(`(?i)Fastly-Debug:\s*`), HeaderCategoryCachePoisoning, 0.75, 0.70, "fastly_debug", `Fastly-Debug: 1`},
	{regexp.MustCompile(`(?i)Vary:.*X-`), HeaderCategoryCachePoisoning, 0.75, 0.70, "vary_custom_header", `Vary: X-Forwarded-Host`},

	// === HTTP/2 Specific (10 patterns) ===
	{regexp.MustCompile(`PRI\s+\*\s+HTTP/2\.0`), HeaderCategoryHTTP2, 0.90, 0.85, "http2_preface", `PRI * HTTP/2.0`},
	{regexp.MustCompile(`(?i):method:\s*`), HeaderCategoryHTTP2, 0.80, 0.75, "h2_pseudo_method", `:method: GET`},
	{regexp.MustCompile(`(?i):path:\s*`), HeaderCategoryHTTP2, 0.80, 0.75, "h2_pseudo_path", `:path: /admin`},
	{regexp.MustCompile(`(?i):authority:\s*`), HeaderCategoryHTTP2, 0.80, 0.75, "h2_pseudo_authority", `:authority: evil.com`},
	{regexp.MustCompile(`(?i):scheme:\s*`), HeaderCategoryHTTP2, 0.80, 0.75, "h2_pseudo_scheme", `:scheme: https`},
	{regexp.MustCompile(`(?i)Upgrade:\s*h2c\b`), HeaderCategoryHTTP2, 0.90, 0.85, "upgrade_h2c", `Upgrade: h2c`},
	{regexp.MustCompile(`(?i)HTTP2-Settings:\s*`), HeaderCategoryHTTP2, 0.85, 0.80, "http2_settings", `HTTP2-Settings: base64`},
	{regexp.MustCompile(`(?i)Connection:\s*Upgrade.*HTTP2`), HeaderCategoryHTTP2, 0.90, 0.85, "connection_upgrade_h2", `Connection: Upgrade, HTTP2-Settings`},
	{regexp.MustCompile(`(?i)Alt-Svc:\s*h2=`), HeaderCategoryHTTP2, 0.75, 0.70, "alt_svc_h2", `Alt-Svc: h2="evil.com:443"`},
	{regexp.MustCompile(`(?i)Sec-WebSocket-`), HeaderCategoryHTTP2, 0.70, 0.65, "sec_websocket", `Sec-WebSocket-Key: base64`},

	// === Security Header Bypass (10 patterns) ===
	{regexp.MustCompile(`(?i)Strict-Transport-Security:\s*max-age=0`), HeaderCategorySecBypass, 0.90, 0.85, "hsts_zero", `Strict-Transport-Security: max-age=0`},
	{regexp.MustCompile(`(?i)Content-Security-Policy:.*unsafe-eval`), HeaderCategorySecBypass, 0.85, 0.80, "csp_unsafe_eval", `Content-Security-Policy: script-src 'unsafe-eval'`},
	{regexp.MustCompile(`(?i)Permissions-Policy:\s*\*`), HeaderCategorySecBypass, 0.80, 0.75, "permissions_policy_star", `Permissions-Policy: *`},
	{regexp.MustCompile(`(?i)Cross-Origin-Opener-Policy:\s*unsafe-none`), HeaderCategorySecBypass, 0.80, 0.75, "coop_unsafe_none", `Cross-Origin-Opener-Policy: unsafe-none`},
	{regexp.MustCompile(`(?i)Cross-Origin-Embedder-Policy:\s*unsafe-none`), HeaderCategorySecBypass, 0.80, 0.75, "coep_unsafe_none", `Cross-Origin-Embedder-Policy: unsafe-none`},
	{regexp.MustCompile(`(?i)Cross-Origin-Resource-Policy:\s*cross-origin`), HeaderCategorySecBypass, 0.75, 0.70, "corp_cross_origin", `Cross-Origin-Resource-Policy: cross-origin`},
	{regexp.MustCompile(`(?i)X-Permitted-Cross-Domain-Policies:\s*all`), HeaderCategorySecBypass, 0.85, 0.80, "xpcdp_all", `X-Permitted-Cross-Domain-Policies: all`},
	{regexp.MustCompile(`(?i)Referrer-Policy:\s*unsafe-url`), HeaderCategorySecBypass, 0.80, 0.75, "referrer_unsafe_url", `Referrer-Policy: unsafe-url`},
	{regexp.MustCompile(`(?i)Feature-Policy:\s*\*`), HeaderCategorySecBypass, 0.80, 0.75, "feature_policy_star", `Feature-Policy: *`},
	{regexp.MustCompile(`(?i)Access-Control-Allow-Credentials:\s*true`), HeaderCategorySecBypass, 0.85, 0.80, "acao_credentials_true", `Access-Control-Allow-Credentials: true`},

	// === Advanced Smuggling (8 patterns) ===
	{regexp.MustCompile(`\r\n[\t ]+\w`), HeaderCategoryAdvSmuggling, 0.85, 0.80, "obs_fold_header", "Header: val\r\n\tcontinuation"},
	{regexp.MustCompile(`(?i)Transfer-Encoding:\s*(?:cow|chunKed|CHUNK)\b`), HeaderCategoryAdvSmuggling, 0.95, 0.90, "te_invalid_values", `Transfer-Encoding: cow`},
	{regexp.MustCompile(`(?i)Content-Length:\s*-\d+`), HeaderCategoryAdvSmuggling, 0.95, 0.90, "negative_content_length", `Content-Length: -1`},
	{regexp.MustCompile(`(?i)Content-Length:\s*\+\d+`), HeaderCategoryAdvSmuggling, 0.85, 0.80, "plus_prefix_cl", `Content-Length: +42`},
	{regexp.MustCompile(`(?i)Content-Length:\s*0x[0-9a-f]+`), HeaderCategoryAdvSmuggling, 0.90, 0.85, "hex_content_length", `Content-Length: 0x2a`},
	{regexp.MustCompile(`(?i)Content-Length:\s*\d+e\d+`), HeaderCategoryAdvSmuggling, 0.90, 0.85, "scientific_cl", `Content-Length: 1e2`},
	{regexp.MustCompile(`(?i)Content-Length:\s*\d+\.\d+`), HeaderCategoryAdvSmuggling, 0.85, 0.80, "decimal_cl", `Content-Length: 42.0`},
	{regexp.MustCompile(`(?i)Trailer:\s*`), HeaderCategoryAdvSmuggling, 0.70, 0.65, "trailer_header", `Trailer: Transfer-Encoding`},
}

// CheckHeaderInjection checks input for HTTP header injection patterns and returns all findings.
func CheckHeaderInjection(input string) []HeaderInjectionFinding {
	if len(input) == 0 {
		return nil
	}

	var findings []HeaderInjectionFinding

	// Quick pre-filter
	if !strings.ContainsAny(input, ":%\r\n") && !strings.Contains(input, "HTTP") {
		return nil
	}

	for i := range HeaderInjectionPatterns {
		p := &HeaderInjectionPatterns[i]
		if p.Pattern.MatchString(input) {
			findings = append(findings, HeaderInjectionFinding{
				Pattern:    p,
				MatchedStr: p.Pattern.FindString(input),
			})
		}
	}
	return findings
}

// HeaderInjectionFinding represents a matched header injection pattern.
type HeaderInjectionFinding struct {
	Pattern    *HeaderInjectionPattern
	MatchedStr string
}
