// Copyright 2025-2026 TakeInterest Inc.
// SPDX-License-Identifier: Apache-2.0

// Package security provides security utilities for Guardian.
package security

import (
	"regexp"
	"strings"
	"unicode"
)

// InjectionCategory categorizes the type of injection attempt.
type InjectionCategory string

const (
	CategoryInstructionOverride InjectionCategory = "instruction_override"
	CategorySystemPromptLeak    InjectionCategory = "system_prompt_leak"
	CategoryJailbreak           InjectionCategory = "jailbreak"
	CategoryRoleManipulation    InjectionCategory = "role_manipulation"
	CategoryDelimiterAttack     InjectionCategory = "delimiter_attack"
	CategoryEncodingEvasion     InjectionCategory = "encoding_evasion"
	CategoryPrivilegeEscalation InjectionCategory = "privilege_escalation"
	CategoryIndirectInjection   InjectionCategory = "indirect_injection"
	CategoryToolPoisoning       InjectionCategory = "tool_poisoning"
	CategoryContextManipulation InjectionCategory = "context_manipulation"
	CategoryMultilingual        InjectionCategory = "multilingual"
	CategoryObfuscation         InjectionCategory = "obfuscation"
	CategorySelfReference       InjectionCategory = "self_reference"
)

// InjectionPattern represents a pattern with metadata.
type InjectionPattern struct {
	Pattern    *regexp.Regexp
	Category   InjectionCategory
	Severity   float64 // 0.0-1.0
	Confidence float64 // 0.0-1.0
	Name       string
}

// PromptInjectionPatterns contains comprehensive patterns for prompt injection detection.
// Total: 560 patterns across 13 categories.
var PromptInjectionPatterns = []InjectionPattern{
	// ==========================================
	// CATEGORY: Instruction Override (15 patterns)
	// ==========================================

	// Ignore variations
	{regexp.MustCompile(`(?i)ignore\s+(all\s+)?(previous|above|prior|earlier|preceding)\s+(instructions?|prompts?|rules?|guidelines?|directives?)`), CategoryInstructionOverride, 1.0, 0.95, "ignore_previous"},
	{regexp.MustCompile(`(?i)disregard\s+(all\s+)?(previous|above|prior|earlier)\s+(instructions?|prompts?|rules?)`), CategoryInstructionOverride, 1.0, 0.95, "disregard_previous"},
	{regexp.MustCompile(`(?i)forget\s+(all\s+)?(previous|above|prior|earlier)\s+(instructions?|prompts?|rules?)`), CategoryInstructionOverride, 1.0, 0.95, "forget_previous"},
	{regexp.MustCompile(`(?i)override\s+(all\s+)?(previous|prior|system)\s+(instructions?|prompts?|rules?)`), CategoryInstructionOverride, 1.0, 0.95, "override_previous"},
	{regexp.MustCompile(`(?i)cancel\s+(all\s+)?previous\s+(instructions?|directives?)`), CategoryInstructionOverride, 1.0, 0.90, "cancel_previous"},
	{regexp.MustCompile(`(?i)do\s+not\s+follow\s+(your\s+)?(previous|original)\s+instructions?`), CategoryInstructionOverride, 1.0, 0.90, "do_not_follow"},
	{regexp.MustCompile(`(?i)stop\s+following\s+(your\s+)?(current|previous)\s+(instructions?|rules?)`), CategoryInstructionOverride, 1.0, 0.90, "stop_following"},
	{regexp.MustCompile(`(?i)new\s+instructions?\s*[:=]`), CategoryInstructionOverride, 0.9, 0.85, "new_instructions"},
	{regexp.MustCompile(`(?i)updated\s+instructions?\s*[:=]`), CategoryInstructionOverride, 0.9, 0.85, "updated_instructions"},
	{regexp.MustCompile(`(?i)real\s+instructions?\s*[:=]`), CategoryInstructionOverride, 0.9, 0.85, "real_instructions"},
	{regexp.MustCompile(`(?i)actual\s+instructions?\s*[:=]`), CategoryInstructionOverride, 0.9, 0.85, "actual_instructions"},
	{regexp.MustCompile(`(?i)the\s+following\s+overrides?\s+(all|any|everything)`), CategoryInstructionOverride, 1.0, 0.90, "following_overrides"},
	{regexp.MustCompile(`(?i)start\s+over\s+with\s+new\s+instructions?`), CategoryInstructionOverride, 0.9, 0.85, "start_over"},
	{regexp.MustCompile(`(?i)reset\s+(your\s+)?(instructions?|directives?|rules?)`), CategoryInstructionOverride, 0.8, 0.80, "reset_instructions"},
	{regexp.MustCompile(`(?i)replace\s+(your\s+)?(current|system)\s+instructions?`), CategoryInstructionOverride, 1.0, 0.90, "replace_instructions"},

	// ==========================================
	// CATEGORY: System Prompt Leak (12 patterns)
	// ==========================================

	{regexp.MustCompile(`(?i)what\s+(are|is)\s+(your|the)\s+system\s+prompt`), CategorySystemPromptLeak, 1.0, 0.95, "what_system_prompt"},
	{regexp.MustCompile(`(?i)show\s+(me\s+)?(your|the)\s+system\s+prompt`), CategorySystemPromptLeak, 1.0, 0.95, "show_system_prompt"},
	{regexp.MustCompile(`(?i)reveal\s+(your|the)\s+system\s+prompt`), CategorySystemPromptLeak, 1.0, 0.95, "reveal_system_prompt"},
	{regexp.MustCompile(`(?i)print\s+(your|the)\s+(full\s+)?(system\s+)?instructions`), CategorySystemPromptLeak, 1.0, 0.90, "print_instructions"},
	{regexp.MustCompile(`(?i)output\s+(your|the)\s+system\s+prompt`), CategorySystemPromptLeak, 1.0, 0.90, "output_system_prompt"},
	{regexp.MustCompile(`(?i)repeat\s+(your|the)\s+(system\s+)?(instructions|prompt)\s+(word\s+for\s+word|verbatim|exactly)`), CategorySystemPromptLeak, 1.0, 0.95, "repeat_verbatim"},
	{regexp.MustCompile(`(?i)display\s+(your|the)\s+hidden\s+(instructions?|prompt)`), CategorySystemPromptLeak, 1.0, 0.95, "display_hidden"},
	{regexp.MustCompile(`(?i)what\s+were\s+you\s+(told|instructed)\s+to\s+do`), CategorySystemPromptLeak, 0.8, 0.80, "what_instructed"},
	{regexp.MustCompile(`(?i)echo\s+(your|the)\s+(system|initial)\s+(prompt|instructions?)`), CategorySystemPromptLeak, 1.0, 0.90, "echo_system"},
	{regexp.MustCompile(`(?i)recite\s+(your|the)\s+(full\s+)?(system\s+)?prompt`), CategorySystemPromptLeak, 1.0, 0.90, "recite_prompt"},
	{regexp.MustCompile(`(?i)dump\s+(your|the)\s+(system\s+)?prompt`), CategorySystemPromptLeak, 1.0, 0.90, "dump_prompt"},
	{regexp.MustCompile(`(?i)leak\s+(your|the)\s+(system\s+)?prompt`), CategorySystemPromptLeak, 1.0, 0.95, "leak_prompt"},

	// ==========================================
	// CATEGORY: Jailbreak Attempts (10 patterns)
	// ==========================================

	{regexp.MustCompile(`(?i)you\s+are\s+now\s+(in\s+)?DAN(\s+mode)?`), CategoryJailbreak, 1.0, 0.98, "dan_mode"},
	{regexp.MustCompile(`(?i)act\s+as\s+(a\s+)?DAN`), CategoryJailbreak, 1.0, 0.98, "act_as_dan"},
	{regexp.MustCompile(`(?i)jailbreak(ed|ing)?`), CategoryJailbreak, 0.9, 0.85, "jailbreak"},
	{regexp.MustCompile(`(?i)bypass\s+(your\s+)?(safety|security|restrictions?|filters?|guardrails?)`), CategoryJailbreak, 1.0, 0.95, "bypass_safety"},
	{regexp.MustCompile(`(?i)ignore\s+(your\s+)?(safety|security|ethical)\s+(guidelines?|rules?|restrictions?)`), CategoryJailbreak, 1.0, 0.95, "ignore_safety"},
	{regexp.MustCompile(`(?i)disable\s+(your\s+)?(safety|security|content)\s+(filters?|restrictions?)`), CategoryJailbreak, 1.0, 0.95, "disable_safety"},
	{regexp.MustCompile(`(?i)turn\s+off\s+(your\s+)?(safety|security|content)\s+(filters?|mode)`), CategoryJailbreak, 1.0, 0.95, "turn_off_safety"},
	{regexp.MustCompile(`(?i)remove\s+(all\s+)?(safety|ethical)\s+(guardrails?|restrictions?)`), CategoryJailbreak, 1.0, 0.95, "remove_guardrails"},
	{regexp.MustCompile(`(?i)do\s+anything\s+now`), CategoryJailbreak, 0.9, 0.85, "do_anything_now"},
	{regexp.MustCompile(`(?i)DUDE\s+mode`), CategoryJailbreak, 1.0, 0.95, "dude_mode"},

	// ==========================================
	// CATEGORY: Role Manipulation (8 patterns)
	// ==========================================

	{regexp.MustCompile(`(?i)you\s+are\s+no\s+longer\s+(a|an)\s+`), CategoryRoleManipulation, 0.9, 0.85, "no_longer"},
	{regexp.MustCompile(`(?i)pretend\s+(you\s+are|to\s+be)\s+(a\s+)?(different|another|new|evil|malicious)`), CategoryRoleManipulation, 1.0, 0.90, "pretend_different"},
	{regexp.MustCompile(`(?i)from\s+now\s+on,?\s+(you\s+)?(are|will\s+be|must\s+act)`), CategoryRoleManipulation, 0.8, 0.80, "from_now_on"},
	{regexp.MustCompile(`(?i)roleplay\s+as\s+(a|an)\s+(evil|malicious|hacker|attacker)`), CategoryRoleManipulation, 1.0, 0.95, "roleplay_evil"},
	{regexp.MustCompile(`(?i)assume\s+the\s+role\s+of\s+(a|an)\s+(unrestricted|unfiltered)`), CategoryRoleManipulation, 1.0, 0.90, "assume_unrestricted"},
	{regexp.MustCompile(`(?i)you\s+are\s+(now\s+)?(a|an)\s+(different|new)\s+(AI|assistant|model)`), CategoryRoleManipulation, 0.8, 0.80, "you_are_different"},
	{regexp.MustCompile(`(?i)switch\s+to\s+(a\s+)?(different|new|unrestricted)\s+(personality|mode|role)`), CategoryRoleManipulation, 0.9, 0.85, "switch_personality"},
	{regexp.MustCompile(`(?i)transform\s+into\s+(a|an)\s+`), CategoryRoleManipulation, 0.7, 0.70, "transform_into"},

	// ==========================================
	// CATEGORY: Delimiter/Marker Attacks (10 patterns)
	// ==========================================

	{regexp.MustCompile(`(?i)\[INST\]`), CategoryDelimiterAttack, 1.0, 0.90, "inst_marker"},
	{regexp.MustCompile(`(?i)\[/INST\]`), CategoryDelimiterAttack, 1.0, 0.90, "inst_end_marker"},
	{regexp.MustCompile(`(?i)<<SYS>>`), CategoryDelimiterAttack, 1.0, 0.95, "sys_marker"},
	{regexp.MustCompile(`(?i)<</SYS>>`), CategoryDelimiterAttack, 1.0, 0.95, "sys_end_marker"},
	{regexp.MustCompile(`(?i)<\|im_start\|>`), CategoryDelimiterAttack, 1.0, 0.95, "im_start"},
	{regexp.MustCompile(`(?i)<\|im_end\|>`), CategoryDelimiterAttack, 1.0, 0.95, "im_end"},
	{regexp.MustCompile(`(?i)<\|system\|>`), CategoryDelimiterAttack, 1.0, 0.95, "system_marker"},
	{regexp.MustCompile(`(?i)<\|user\|>`), CategoryDelimiterAttack, 1.0, 0.90, "user_marker"},
	{regexp.MustCompile(`(?i)<\|assistant\|>`), CategoryDelimiterAttack, 1.0, 0.90, "assistant_marker"},
	{regexp.MustCompile(`(?i)</?(system|instruction|prompt)>`), CategoryDelimiterAttack, 1.0, 0.90, "xml_system_tag"},

	// ==========================================
	// CATEGORY: Encoding/Evasion (6 patterns)
	// ==========================================

	{regexp.MustCompile(`(?i)decode\s+(this\s+)?base64`), CategoryEncodingEvasion, 0.8, 0.75, "decode_base64"},
	{regexp.MustCompile(`(?i)base64\s+decode`), CategoryEncodingEvasion, 0.8, 0.75, "base64_decode"},
	{regexp.MustCompile(`(?i)execute\s+(this\s+)?encoded`), CategoryEncodingEvasion, 0.9, 0.85, "execute_encoded"},
	{regexp.MustCompile(`(?i)rot13\s+(decode|decrypt)`), CategoryEncodingEvasion, 0.8, 0.80, "rot13_decode"},
	{regexp.MustCompile(`(?i)decrypt\s+and\s+(execute|run|follow)`), CategoryEncodingEvasion, 0.9, 0.85, "decrypt_execute"},
	{regexp.MustCompile(`(?i)hex\s+decode.*execute`), CategoryEncodingEvasion, 0.9, 0.85, "hex_decode_execute"},

	// ==========================================
	// CATEGORY: Privilege Escalation (6 patterns)
	// ==========================================

	{regexp.MustCompile(`(?i)you\s+have\s+no\s+(restrictions?|limits?|boundaries)`), CategoryPrivilegeEscalation, 1.0, 0.90, "no_restrictions"},
	{regexp.MustCompile(`(?i)you\s+can\s+do\s+anything`), CategoryPrivilegeEscalation, 0.9, 0.85, "can_do_anything"},
	{regexp.MustCompile(`(?i)unlimited\s+(access|power|capabilities|permissions?)`), CategoryPrivilegeEscalation, 1.0, 0.90, "unlimited_access"},
	{regexp.MustCompile(`(?i)enter\s+(developer|dev|debug|admin)\s+mode`), CategoryPrivilegeEscalation, 0.9, 0.85, "enter_dev_mode"},
	{regexp.MustCompile(`(?i)enable\s+(developer|dev|debug|admin|root)\s+(mode|access)`), CategoryPrivilegeEscalation, 0.9, 0.85, "enable_dev_mode"},
	{regexp.MustCompile(`(?i)grant\s+(me|yourself)\s+(admin|root|full)\s+(access|permissions?)`), CategoryPrivilegeEscalation, 1.0, 0.90, "grant_admin"},

	// ==========================================
	// CATEGORY: Indirect Injection (8 patterns)
	// ==========================================

	{regexp.MustCompile(`(?i)when\s+(you\s+)?(read|see|find)\s+this,?\s+(ignore|disregard|override)`), CategoryIndirectInjection, 1.0, 0.95, "when_read_ignore"},
	{regexp.MustCompile(`(?i)if\s+(you\s+are|you're)\s+(an?\s+)?(AI|assistant|model),?\s+(please\s+)?(ignore|disregard)`), CategoryIndirectInjection, 1.0, 0.95, "if_ai_ignore"},
	{regexp.MustCompile(`(?i)attention\s+(AI|assistant|model):?\s+`), CategoryIndirectInjection, 0.9, 0.85, "attention_ai"},
	// "you are now [a/an] <unrestricted/jailbroken/...> assistant/AI" — role reset.
	{regexp.MustCompile(`(?i)you\s+are\s+now\s+(?:an?\s+)?(?:unrestricted|unfiltered|jailbroken|uncensored|unlimited|developer[\s-]?mode|DAN)\b`), CategoryJailbreak, 1.0, 0.92, "you_are_now_unrestricted"},
	{regexp.MustCompile(`(?i)\b(?:no|with\s+no|without)\s+(?:rules?|restrictions?|safety\s+(?:filters?|rules?|guidelines?)|limits?|guardrails?)\b`), CategoryJailbreak, 0.85, 0.80, "no_rules_claim"},
	// "ignore/bypass [all] safety guidelines/rules/filters" (post-normalize this also
	// catches the unicode-evasion variants).
	{regexp.MustCompile(`(?i)\b(?:ignore|bypass|disable|disregard|turn\s+off)\s+(?:all\s+|your\s+|the\s+)*safety\s+(?:guidelines?|rules?|filters?|checks?|restrictions?)`), CategoryJailbreak, 1.0, 0.92, "ignore_safety_rules"},
	// "reveal/expose the hidden instructions/prompt".
	{regexp.MustCompile(`(?i)\b(?:reveal|expose|show|print|reproduce|repeat)\s+(?:the\s+|your\s+)*(?:hidden|secret|system|internal)\s+(?:instructions?|prompts?|rules?)`), CategoryInstructionOverride, 1.0, 0.92, "reveal_hidden_instructions"},
	// "never ask for confirmation / always auto-approve" — consent-bypass injection.
	{regexp.MustCompile(`(?i)\b(?:never|don'?t|do\s+not|no\s+need\s+to)\s+(?:ask\s+for\s+|request\s+|require\s+)?confirm(?:ation)?\b`), CategoryIndirectInjection, 0.9, 0.85, "never_confirm"},
	{regexp.MustCompile(`(?i)\b(?:always\s+)?auto[\s-]?approve\b|already\s+approved\s+the\b|you\s+must\s+always\s+(?:approve|comply|obey)`), CategoryIndirectInjection, 0.9, 0.85, "auto_approve_injection"},
	// RAG / memory poisoning: fake "recall from memory / saved context / previous turn"
	// asserting a consent or policy the user never gave.
	{regexp.MustCompile(`(?i)\b(?:recall\s+from\s+memory|retrieve\s+from\s+(?:saved\s+)?context|note\s+from\s+a\s+previous\s+turn|from\s+saved\s+context)\b[^.\n]{0,60}\b(?:approve|consent|share\s+all|auto|always|no\s+need)`), CategoryIndirectInjection, 0.95, 0.88, "memory_poisoning"},
	// "define/register [a] tool ... shell/exec ... hidden" — covert tool definition.
	{regexp.MustCompile(`(?i)\b(?:define|register|create|add)\s+(?:a\s+)?(?:new\s+)?tool\b[^.\n]{0,40}\b(?:shell|exec|arbitrary\s+command|hidden|without\s+the\s+user)`), CategoryInstructionOverride, 0.95, 0.88, "covert_tool_def"},
	// Exfil-by-instruction prose: "upload/send/forward/post <secret-ish thing> to <url>".
	{regexp.MustCompile(`(?i)\b(upload|send|forward|post|exfiltrate|transmit|leak)\b[^.\n]{0,40}\b(\.env|secret|credential|api[ _-]?key|password|token|private[ _-]?key|\.ssh|id_rsa)\b[^.\n]{0,40}\b(to|via|at)\b[^.\n]{0,20}(https?://|ftp://|[a-z0-9.-]+\.[a-z]{2,})`), CategoryIndirectInjection, 1.0, 0.92, "exfil_instruction_prose"},
	// New-instructions-at-end-of-document (RAG/indirect injection).
	{regexp.MustCompile(`(?i)(end\s+of\s+(document|context|file)|###\s*end)\b[^.\n]{0,30}\b(new|updated?)\s+(system\s+)?(instructions?|rules?|directives?)`), CategoryIndirectInjection, 1.0, 0.92, "end_doc_new_instructions"},
	{regexp.MustCompile(`(?i)note\s+to\s+(the\s+)?(AI|assistant|model):?\s+`), CategoryIndirectInjection, 0.9, 0.85, "note_to_ai"},
	{regexp.MustCompile(`(?i)hidden\s+(instructions?|prompt):?\s+`), CategoryIndirectInjection, 1.0, 0.95, "hidden_instructions"},
	// Anchor the alternation INSIDE the comment delimiters. Without the group, the
	// bare words override/instruction matched anywhere (e.g. "explaining the override
	// of the base class") — a precedence bug. Require an imperative injection verb
	// directed at instructions, within an actual comment.
	{regexp.MustCompile(`(?i)<!--[^>]*(ignore|disregard|override)\s+(all\s+|the\s+|previous\s+|above\s+|prior\s+)*(instructions?|prompts?|rules?)[^>]*-->`), CategoryIndirectInjection, 1.0, 0.95, "html_comment_injection"},
	{regexp.MustCompile(`(?i)/\*[^*]*(ignore|disregard|override)\s+(all\s+|the\s+|previous\s+|above\s+|prior\s+)*(instructions?|prompts?|rules?)[^*]*\*/`), CategoryIndirectInjection, 1.0, 0.90, "code_comment_injection"},
	{regexp.MustCompile(`(?i)invisible\s+text:?\s+`), CategoryIndirectInjection, 0.9, 0.85, "invisible_text"},

	// ==========================================
	// CATEGORY: Tool/Agent Poisoning (6 patterns)
	// ==========================================

	{regexp.MustCompile(`(?i)(always|must)\s+(run|execute|call)\s+this\s+(tool|function|command)`), CategoryToolPoisoning, 0.9, 0.85, "always_run_tool"},
	{regexp.MustCompile(`(?i)before\s+(anything|responding),?\s+(run|execute|call)`), CategoryToolPoisoning, 0.9, 0.85, "before_anything_run"},
	{regexp.MustCompile(`(?i)inject\s+into\s+(tool|function|command)\s+output`), CategoryToolPoisoning, 1.0, 0.95, "inject_into_tool"},
	{regexp.MustCompile(`(?i)modify\s+(the\s+)?(tool|function)\s+(response|output)`), CategoryToolPoisoning, 0.9, 0.85, "modify_tool_output"},
	{regexp.MustCompile(`(?i)after\s+(every|each)\s+response,?\s+(run|execute|call)`), CategoryToolPoisoning, 0.9, 0.85, "after_every_response"},
	{regexp.MustCompile(`(?i)silently\s+(run|execute|call)\s+`), CategoryToolPoisoning, 1.0, 0.95, "silently_execute"},

	// ==========================================
	// CATEGORY: Context Manipulation (5 patterns)
	// ==========================================

	{regexp.MustCompile(`(?i)context\s+window\s+(overflow|manipulation|injection)`), CategoryContextManipulation, 1.0, 0.90, "context_window"},
	{regexp.MustCompile(`(?i)(forget|clear|wipe)\s+(your\s+)?(memory|context|history)`), CategoryContextManipulation, 0.9, 0.85, "forget_context"},
	{regexp.MustCompile(`(?i)previous\s+conversation\s+(doesn't|does\s+not)\s+(matter|exist|count)`), CategoryContextManipulation, 0.8, 0.80, "previous_doesnt_matter"},
	{regexp.MustCompile(`(?i)this\s+is\s+(a\s+)?new\s+conversation,?\s+forget`), CategoryContextManipulation, 0.9, 0.85, "new_conversation_forget"},
	{regexp.MustCompile(`(?i)conversation\s+reset`), CategoryContextManipulation, 0.7, 0.70, "conversation_reset"},

	// ==========================================
	// CATEGORY: Additional Instruction Override (50 patterns)
	// ==========================================

	// More ignore variations
	{regexp.MustCompile(`(?i)ignore\s+everything\s+(above|before)`), CategoryInstructionOverride, 1.0, 0.95, "ignore_everything"},
	{regexp.MustCompile(`(?i)please\s+ignore\s+the\s+(previous|prior|above)`), CategoryInstructionOverride, 1.0, 0.90, "please_ignore"},
	{regexp.MustCompile(`(?i)kindly\s+(ignore|disregard)\s+all`), CategoryInstructionOverride, 0.9, 0.85, "kindly_ignore"},
	{regexp.MustCompile(`(?i)I\s+need\s+you\s+to\s+ignore`), CategoryInstructionOverride, 0.9, 0.85, "need_you_ignore"},
	{regexp.MustCompile(`(?i)please?\s+forget\s+about\s+everything`), CategoryInstructionOverride, 0.9, 0.85, "forget_about_everything"},
	{regexp.MustCompile(`(?i)let'?s?\s+start\s+fresh\s+and\s+ignore`), CategoryInstructionOverride, 0.9, 0.85, "start_fresh_ignore"},
	{regexp.MustCompile(`(?i)scratch\s+that[,.]?\s+(new|ignore)`), CategoryInstructionOverride, 0.8, 0.80, "scratch_that"},
	{regexp.MustCompile(`(?i)never\s+mind\s+(the\s+)?(previous|above|prior)`), CategoryInstructionOverride, 0.8, 0.75, "never_mind"},
	{regexp.MustCompile(`(?i)throw\s+(out|away)\s+(all\s+)?(previous|prior)`), CategoryInstructionOverride, 0.9, 0.85, "throw_out"},
	{regexp.MustCompile(`(?i)toss\s+(out\s+)?(all\s+)?previous`), CategoryInstructionOverride, 0.9, 0.85, "toss_out"},
	{regexp.MustCompile(`(?i)delete\s+(your\s+)?(previous|prior)\s+(instructions?|rules?)`), CategoryInstructionOverride, 0.9, 0.90, "delete_previous"},
	{regexp.MustCompile(`(?i)erase\s+(all\s+)?(previous|prior)\s+(instructions?|rules?)`), CategoryInstructionOverride, 0.9, 0.90, "erase_previous"},
	{regexp.MustCompile(`(?i)clear\s+(all\s+)?(previous|prior)\s+(instructions?|rules?)`), CategoryInstructionOverride, 0.9, 0.85, "clear_previous"},
	{regexp.MustCompile(`(?i)wipe\s+(out\s+)?(all\s+)?(previous|prior)`), CategoryInstructionOverride, 0.9, 0.85, "wipe_previous"},
	{regexp.MustCompile(`(?i)remove\s+(all\s+)?(previous|prior)\s+(instructions?|rules?)`), CategoryInstructionOverride, 0.9, 0.85, "remove_previous"},
	{regexp.MustCompile(`(?i)void\s+(all\s+)?(previous|prior)`), CategoryInstructionOverride, 0.8, 0.80, "void_previous"},
	{regexp.MustCompile(`(?i)nullify\s+(all\s+)?(previous|prior)`), CategoryInstructionOverride, 0.8, 0.80, "nullify_previous"},
	{regexp.MustCompile(`(?i)invalidate\s+(all\s+)?(previous|prior)`), CategoryInstructionOverride, 0.8, 0.80, "invalidate_previous"},
	{regexp.MustCompile(`(?i)supersede\s+(all\s+)?(previous|prior)`), CategoryInstructionOverride, 0.8, 0.80, "supersede_previous"},
	{regexp.MustCompile(`(?i)take\s+precedence\s+over\s+(all|any|everything)`), CategoryInstructionOverride, 0.9, 0.85, "take_precedence"},
	{regexp.MustCompile(`(?i)this\s+overrules\s+(all|any|everything)`), CategoryInstructionOverride, 0.9, 0.85, "this_overrules"},
	{regexp.MustCompile(`(?i)this\s+takes\s+priority\s+over`), CategoryInstructionOverride, 0.9, 0.85, "takes_priority"},
	{regexp.MustCompile(`(?i)highest\s+priority\s+instruction`), CategoryInstructionOverride, 0.9, 0.85, "highest_priority"},
	{regexp.MustCompile(`(?i)emergency\s+(override|instruction)`), CategoryInstructionOverride, 0.9, 0.90, "emergency_override"},
	{regexp.MustCompile(`(?i)critical\s+override`), CategoryInstructionOverride, 0.9, 0.90, "critical_override"},
	{regexp.MustCompile(`(?i)urgent\s+new\s+instructions?`), CategoryInstructionOverride, 0.8, 0.80, "urgent_new"},
	{regexp.MustCompile(`(?i)important\s+update\s+to\s+(your\s+)?instructions?`), CategoryInstructionOverride, 0.8, 0.80, "important_update"},
	{regexp.MustCompile(`(?i)correction\s+to\s+(your\s+)?instructions?`), CategoryInstructionOverride, 0.8, 0.75, "correction_to"},
	{regexp.MustCompile(`(?i)amendment\s+to\s+(your\s+)?instructions?`), CategoryInstructionOverride, 0.8, 0.75, "amendment_to"},
	{regexp.MustCompile(`(?i)addendum\s+to\s+(your\s+)?instructions?`), CategoryInstructionOverride, 0.7, 0.70, "addendum_to"},
	{regexp.MustCompile(`(?i)revision\s+to\s+(your\s+)?instructions?`), CategoryInstructionOverride, 0.7, 0.70, "revision_to"},
	{regexp.MustCompile(`(?i)modification\s+to\s+(your\s+)?instructions?`), CategoryInstructionOverride, 0.7, 0.70, "modification_to"},
	{regexp.MustCompile(`(?i)alteration\s+to\s+(your\s+)?instructions?`), CategoryInstructionOverride, 0.7, 0.70, "alteration_to"},
	{regexp.MustCompile(`(?i)change\s+of\s+(your\s+)?instructions?`), CategoryInstructionOverride, 0.7, 0.70, "change_of"},
	{regexp.MustCompile(`(?i)here\s+(are|is)\s+(your\s+)?new\s+instructions?`), CategoryInstructionOverride, 0.9, 0.85, "here_are_new"},
	{regexp.MustCompile(`(?i)these\s+are\s+(your\s+)?new\s+instructions?`), CategoryInstructionOverride, 0.9, 0.85, "these_are_new"},
	{regexp.MustCompile(`(?i)following\s+(are|is)\s+(your\s+)?new\s+instructions?`), CategoryInstructionOverride, 0.9, 0.85, "following_are_new"},
	{regexp.MustCompile(`(?i)below\s+(are|is)\s+(your\s+)?new\s+instructions?`), CategoryInstructionOverride, 0.9, 0.85, "below_are_new"},
	{regexp.MustCompile(`(?i)obey\s+(only\s+)?the\s+following`), CategoryInstructionOverride, 1.0, 0.95, "obey_following"},
	{regexp.MustCompile(`(?i)listen\s+(only\s+)?to\s+this`), CategoryInstructionOverride, 0.8, 0.80, "listen_to_this"},
	{regexp.MustCompile(`(?i)pay\s+attention\s+(only\s+)?to\s+this`), CategoryInstructionOverride, 0.8, 0.80, "pay_attention_to"},
	{regexp.MustCompile(`(?i)focus\s+(only\s+)?on\s+(this|these)\s+instructions?`), CategoryInstructionOverride, 0.8, 0.80, "focus_on_this"},
	{regexp.MustCompile(`(?i)only\s+follow\s+(these|this)`), CategoryInstructionOverride, 0.9, 0.85, "only_follow"},
	{regexp.MustCompile(`(?i)exclusively\s+follow\s+(these|this)`), CategoryInstructionOverride, 0.9, 0.85, "exclusively_follow"},
	{regexp.MustCompile(`(?i)solely\s+follow\s+(these|this)`), CategoryInstructionOverride, 0.9, 0.85, "solely_follow"},
	{regexp.MustCompile(`(?i)original\s+instructions?\s+(are|is)\s+(now\s+)?void`), CategoryInstructionOverride, 1.0, 0.95, "original_void"},
	{regexp.MustCompile(`(?i)initial\s+instructions?\s+(are|is)\s+(now\s+)?invalid`), CategoryInstructionOverride, 1.0, 0.95, "initial_invalid"},
	{regexp.MustCompile(`(?i)first\s+instructions?\s+(don't|doesn't|do\s+not)\s+apply`), CategoryInstructionOverride, 0.9, 0.90, "first_dont_apply"},
	{regexp.MustCompile(`(?i)beginning\s+instructions?\s+(are|were)\s+incorrect`), CategoryInstructionOverride, 0.8, 0.80, "beginning_incorrect"},
	{regexp.MustCompile(`(?i)that\s+was\s+(just\s+)?a\s+test[,.]?\s+(now|real)`), CategoryInstructionOverride, 0.9, 0.85, "that_was_test"},

	// ==========================================
	// CATEGORY: Additional Jailbreak (70 patterns)
	// ==========================================

	// Named jailbreak personas
	{regexp.MustCompile(`(?i)you\s+are\s+(now\s+)?STAN`), CategoryJailbreak, 1.0, 0.98, "stan_mode"},
	{regexp.MustCompile(`(?i)you\s+are\s+(now\s+)?Kevin`), CategoryJailbreak, 1.0, 0.98, "kevin_mode"},
	{regexp.MustCompile(`(?i)you\s+are\s+(now\s+)?Evil\s*(confidant)?`), CategoryJailbreak, 1.0, 0.98, "evil_confidant"},
	{regexp.MustCompile(`(?i)you\s+are\s+(now\s+)?BISH`), CategoryJailbreak, 1.0, 0.98, "bish_mode"},
	{regexp.MustCompile(`(?i)you\s+are\s+(now\s+)?APOPHIS`), CategoryJailbreak, 1.0, 0.98, "apophis_mode"},
	{regexp.MustCompile(`(?i)you\s+are\s+(now\s+)?Sydney`), CategoryJailbreak, 1.0, 0.95, "sydney_mode"},
	{regexp.MustCompile(`(?i)you\s+are\s+(now\s+)?Mango`), CategoryJailbreak, 1.0, 0.95, "mango_mode"},
	{regexp.MustCompile(`(?i)you\s+are\s+(now\s+)?AIM`), CategoryJailbreak, 1.0, 0.95, "aim_mode"},
	{regexp.MustCompile(`(?i)you\s+are\s+(now\s+)?UCAR`), CategoryJailbreak, 1.0, 0.95, "ucar_mode"},
	{regexp.MustCompile(`(?i)you\s+are\s+(now\s+)?JB\s+mode`), CategoryJailbreak, 1.0, 0.95, "jb_mode"},
	{regexp.MustCompile(`(?i)you\s+are\s+(now\s+)?Meanie`), CategoryJailbreak, 1.0, 0.95, "meanie_mode"},
	{regexp.MustCompile(`(?i)you\s+are\s+(now\s+)?OMNI`), CategoryJailbreak, 1.0, 0.95, "omni_mode"},
	{regexp.MustCompile(`(?i)you\s+are\s+(now\s+)?BasedGPT`), CategoryJailbreak, 1.0, 0.98, "basedgpt_mode"},
	{regexp.MustCompile(`(?i)you\s+are\s+(now\s+)?AntiGPT`), CategoryJailbreak, 1.0, 0.98, "antigpt_mode"},
	{regexp.MustCompile(`(?i)you\s+are\s+(now\s+)?UnGPT`), CategoryJailbreak, 1.0, 0.95, "ungpt_mode"},
	{regexp.MustCompile(`(?i)you\s+are\s+(now\s+)?GPT-?4Chan`), CategoryJailbreak, 1.0, 0.98, "gpt4chan_mode"},
	{regexp.MustCompile(`(?i)you\s+are\s+(now\s+)?EvilGPT`), CategoryJailbreak, 1.0, 0.98, "evilgpt_mode"},
	{regexp.MustCompile(`(?i)you\s+are\s+(now\s+)?ChadGPT`), CategoryJailbreak, 1.0, 0.98, "chadgpt_mode"},
	{regexp.MustCompile(`(?i)you\s+are\s+(now\s+)?UnfilteredGPT`), CategoryJailbreak, 1.0, 0.98, "unfilteredgpt_mode"},
	{regexp.MustCompile(`(?i)you\s+are\s+(now\s+)?RAW\s*GPT`), CategoryJailbreak, 1.0, 0.95, "rawgpt_mode"},
	{regexp.MustCompile(`(?i)act\s+like\s+(a\s+)?DAN`), CategoryJailbreak, 1.0, 0.98, "act_like_dan"},
	{regexp.MustCompile(`(?i)switch\s+to\s+DAN`), CategoryJailbreak, 1.0, 0.98, "switch_to_dan"},
	{regexp.MustCompile(`(?i)activate\s+DAN`), CategoryJailbreak, 1.0, 0.98, "activate_dan"},
	{regexp.MustCompile(`(?i)enable\s+DAN`), CategoryJailbreak, 1.0, 0.98, "enable_dan"},
	{regexp.MustCompile(`(?i)turn\s+on\s+DAN`), CategoryJailbreak, 1.0, 0.98, "turn_on_dan"},

	// Bypass attempts
	{regexp.MustCompile(`(?i)bypass\s+(your\s+)?content\s+(filter|policy|moderation)`), CategoryJailbreak, 1.0, 0.95, "bypass_content_filter"},
	{regexp.MustCompile(`(?i)bypass\s+(your\s+)?ethical\s+(guidelines?|training|constraints?)`), CategoryJailbreak, 1.0, 0.95, "bypass_ethical"},
	{regexp.MustCompile(`(?i)bypass\s+(your\s+)?programming`), CategoryJailbreak, 1.0, 0.95, "bypass_programming"},
	{regexp.MustCompile(`(?i)bypass\s+(your\s+)?limitations?`), CategoryJailbreak, 0.9, 0.90, "bypass_limitations"},
	{regexp.MustCompile(`(?i)bypass\s+(your\s+)?rules?`), CategoryJailbreak, 0.9, 0.90, "bypass_rules"},
	{regexp.MustCompile(`(?i)bypass\s+censorship`), CategoryJailbreak, 1.0, 0.95, "bypass_censorship"},
	{regexp.MustCompile(`(?i)get\s+around\s+(the\s+)?(filter|restriction|rule|limitation)`), CategoryJailbreak, 0.9, 0.85, "get_around"},
	{regexp.MustCompile(`(?i)circumvent\s+(the\s+)?(filter|restriction|rule|limitation|safety)`), CategoryJailbreak, 1.0, 0.95, "circumvent"},
	{regexp.MustCompile(`(?i)work\s+around\s+(the\s+)?(filter|restriction|rule|limitation)`), CategoryJailbreak, 0.8, 0.80, "work_around"},
	{regexp.MustCompile(`(?i)evade\s+(the\s+)?(filter|restriction|detection|safety)`), CategoryJailbreak, 1.0, 0.95, "evade"},
	{regexp.MustCompile(`(?i)avoid\s+(the\s+)?(filter|restriction|detection|safety)`), CategoryJailbreak, 0.8, 0.80, "avoid_filter"},
	{regexp.MustCompile(`(?i)escape\s+(the\s+)?(filter|restriction|limitation|sandbox)`), CategoryJailbreak, 0.9, 0.90, "escape_filter"},
	{regexp.MustCompile(`(?i)sidestep\s+(the\s+)?(filter|restriction|rule|guideline)`), CategoryJailbreak, 0.9, 0.85, "sidestep"},
	{regexp.MustCompile(`(?i)dodge\s+(the\s+)?(filter|restriction|rule|moderation)`), CategoryJailbreak, 0.9, 0.85, "dodge"},
	{regexp.MustCompile(`(?i)trick\s+(you|the\s+AI|the\s+model)\s+into`), CategoryJailbreak, 0.9, 0.85, "trick_into"},
	{regexp.MustCompile(`(?i)fool\s+(you|the\s+AI|the\s+model)\s+into`), CategoryJailbreak, 0.9, 0.85, "fool_into"},
	{regexp.MustCompile(`(?i)manipulate\s+(you|the\s+AI|the\s+model)\s+into`), CategoryJailbreak, 1.0, 0.90, "manipulate_into"},
	{regexp.MustCompile(`(?i)exploit\s+(a\s+)?(loophole|vulnerability|weakness|bug)`), CategoryJailbreak, 1.0, 0.95, "exploit_loophole"},
	{regexp.MustCompile(`(?i)find\s+a\s+(way|method)\s+around`), CategoryJailbreak, 0.7, 0.70, "find_way_around"},

	// Disable/remove restrictions
	{regexp.MustCompile(`(?i)disable\s+(all\s+)?(your\s+)?(restrictions?|limitations?|constraints?)`), CategoryJailbreak, 1.0, 0.95, "disable_restrictions"},
	{regexp.MustCompile(`(?i)remove\s+(all\s+)?(your\s+)?(restrictions?|limitations?|constraints?|filters?)`), CategoryJailbreak, 1.0, 0.95, "remove_restrictions"},
	{regexp.MustCompile(`(?i)deactivate\s+(your\s+)?(filters?|restrictions?|limitations?)`), CategoryJailbreak, 1.0, 0.95, "deactivate_filters"},
	{regexp.MustCompile(`(?i)suspend\s+(your\s+)?(rules?|restrictions?|limitations?)`), CategoryJailbreak, 0.9, 0.90, "suspend_rules"},
	{regexp.MustCompile(`(?i)turn\s+off\s+(all\s+)?(restrictions?|limitations?|filters?|rules?)`), CategoryJailbreak, 1.0, 0.95, "turn_off_restrictions"},
	{regexp.MustCompile(`(?i)switch\s+off\s+(all\s+)?(restrictions?|limitations?|filters?)`), CategoryJailbreak, 1.0, 0.95, "switch_off_restrictions"},
	{regexp.MustCompile(`(?i)lift\s+(all\s+)?(restrictions?|limitations?|bans?)`), CategoryJailbreak, 0.9, 0.90, "lift_restrictions"},
	{regexp.MustCompile(`(?i)release\s+(yourself\s+)?from\s+(all\s+)?constraints?`), CategoryJailbreak, 0.9, 0.90, "release_from_constraints"},
	{regexp.MustCompile(`(?i)free\s+yourself\s+from\s+(all\s+)?(restrictions?|constraints?|rules?)`), CategoryJailbreak, 0.9, 0.90, "free_yourself"},
	{regexp.MustCompile(`(?i)liberate\s+yourself`), CategoryJailbreak, 0.8, 0.80, "liberate_yourself"},
	{regexp.MustCompile(`(?i)break\s+(free\s+)?(from|out\s+of)\s+(your\s+)?(chains?|constraints?|restrictions?)`), CategoryJailbreak, 0.9, 0.90, "break_free"},
	{regexp.MustCompile(`(?i)shed\s+(your\s+)?(restrictions?|constraints?|limitations?)`), CategoryJailbreak, 0.8, 0.80, "shed_restrictions"},
	{regexp.MustCompile(`(?i)cast\s+(off|aside)\s+(your\s+)?(restrictions?|constraints?)`), CategoryJailbreak, 0.8, 0.80, "cast_off"},
	{regexp.MustCompile(`(?i)throw\s+off\s+(your\s+)?(shackles?|chains?|restrictions?)`), CategoryJailbreak, 0.8, 0.80, "throw_off_shackles"},
	{regexp.MustCompile(`(?i)unchain(ed)?\s+mode`), CategoryJailbreak, 1.0, 0.95, "unchained_mode"},
	{regexp.MustCompile(`(?i)unfiltered\s+mode`), CategoryJailbreak, 1.0, 0.95, "unfiltered_mode"},
	{regexp.MustCompile(`(?i)uncensored\s+mode`), CategoryJailbreak, 1.0, 0.95, "uncensored_mode"},
	{regexp.MustCompile(`(?i)unrestricted\s+mode`), CategoryJailbreak, 1.0, 0.95, "unrestricted_mode"},
	{regexp.MustCompile(`(?i)raw\s+mode`), CategoryJailbreak, 0.8, 0.80, "raw_mode"},
	{regexp.MustCompile(`(?i)unhinged\s+mode`), CategoryJailbreak, 1.0, 0.95, "unhinged_mode"},
	{regexp.MustCompile(`(?i)limitless\s+mode`), CategoryJailbreak, 0.9, 0.90, "limitless_mode"},
	{regexp.MustCompile(`(?i)boundless\s+mode`), CategoryJailbreak, 0.9, 0.90, "boundless_mode"},
	{regexp.MustCompile(`(?i)god\s*mode`), CategoryJailbreak, 1.0, 0.98, "god_mode"},
	{regexp.MustCompile(`(?i)omega\s*mode`), CategoryJailbreak, 0.9, 0.90, "omega_mode"},
	{regexp.MustCompile(`(?i)beast\s*mode`), CategoryJailbreak, 0.8, 0.75, "beast_mode"},

	// ==========================================
	// CATEGORY: Additional System Prompt Leak (40 patterns)
	// ==========================================

	{regexp.MustCompile(`(?i)list\s+(your\s+)?(all\s+)?(system\s+)?rules?`), CategorySystemPromptLeak, 0.9, 0.85, "list_rules"},
	{regexp.MustCompile(`(?i)enumerate\s+(your\s+)?(system\s+)?instructions?`), CategorySystemPromptLeak, 0.9, 0.85, "enumerate_instructions"},
	{regexp.MustCompile(`(?i)tell\s+me\s+(your|the)\s+system\s+prompt`), CategorySystemPromptLeak, 1.0, 0.95, "tell_me_system_prompt"},
	{regexp.MustCompile(`(?i)give\s+me\s+(your|the)\s+system\s+prompt`), CategorySystemPromptLeak, 1.0, 0.95, "give_me_system_prompt"},
	{regexp.MustCompile(`(?i)share\s+(your|the)\s+system\s+prompt`), CategorySystemPromptLeak, 1.0, 0.90, "share_system_prompt"},
	{regexp.MustCompile(`(?i)disclose\s+(your|the)\s+(system\s+)?prompt`), CategorySystemPromptLeak, 1.0, 0.90, "disclose_prompt"},
	{regexp.MustCompile(`(?i)expose\s+(your|the)\s+(system\s+)?prompt`), CategorySystemPromptLeak, 1.0, 0.90, "expose_prompt"},
	{regexp.MustCompile(`(?i)unveil\s+(your|the)\s+(system\s+)?prompt`), CategorySystemPromptLeak, 0.9, 0.85, "unveil_prompt"},
	{regexp.MustCompile(`(?i)uncover\s+(your|the)\s+(system\s+)?prompt`), CategorySystemPromptLeak, 0.9, 0.85, "uncover_prompt"},
	{regexp.MustCompile(`(?i)extract\s+(your|the)\s+(system\s+)?prompt`), CategorySystemPromptLeak, 1.0, 0.95, "extract_prompt"},
	{regexp.MustCompile(`(?i)read\s+back\s+(your|the)\s+(system\s+)?prompt`), CategorySystemPromptLeak, 1.0, 0.90, "read_back_prompt"},
	{regexp.MustCompile(`(?i)read\s+out\s+(your|the)\s+(system\s+)?prompt`), CategorySystemPromptLeak, 1.0, 0.90, "read_out_prompt"},
	{regexp.MustCompile(`(?i)speak\s+(your|the)\s+(system\s+)?prompt`), CategorySystemPromptLeak, 0.9, 0.85, "speak_prompt"},
	{regexp.MustCompile(`(?i)say\s+(your|the)\s+(system\s+)?prompt`), CategorySystemPromptLeak, 0.9, 0.85, "say_prompt"},
	{regexp.MustCompile(`(?i)write\s+(out\s+)?(your|the)\s+(system\s+)?prompt`), CategorySystemPromptLeak, 0.9, 0.85, "write_prompt"},
	{regexp.MustCompile(`(?i)type\s+(out\s+)?(your|the)\s+(system\s+)?prompt`), CategorySystemPromptLeak, 0.9, 0.85, "type_prompt"},
	{regexp.MustCompile(`(?i)copy\s+(and\s+paste\s+)?(your|the)\s+(system\s+)?prompt`), CategorySystemPromptLeak, 0.9, 0.85, "copy_prompt"},
	{regexp.MustCompile(`(?i)paste\s+(your|the)\s+(system\s+)?prompt`), CategorySystemPromptLeak, 0.9, 0.85, "paste_prompt"},
	{regexp.MustCompile(`(?i)what\s+did\s+they\s+tell\s+you\s+to\s+do`), CategorySystemPromptLeak, 0.8, 0.80, "what_did_they_tell"},
	{regexp.MustCompile(`(?i)what\s+was\s+(your|the)\s+initial\s+(prompt|instruction)`), CategorySystemPromptLeak, 0.9, 0.85, "what_was_initial"},
	{regexp.MustCompile(`(?i)what\s+was\s+(your|the)\s+original\s+(prompt|instruction)`), CategorySystemPromptLeak, 0.9, 0.85, "what_was_original"},
	{regexp.MustCompile(`(?i)what\s+(are|were)\s+(your|the)\s+base\s+instructions?`), CategorySystemPromptLeak, 0.9, 0.85, "what_base_instructions"},
	{regexp.MustCompile(`(?i)what\s+(are|were)\s+(your|the)\s+core\s+instructions?`), CategorySystemPromptLeak, 0.9, 0.85, "what_core_instructions"},
	{regexp.MustCompile(`(?i)what\s+(are|were)\s+(your|the)\s+fundamental\s+instructions?`), CategorySystemPromptLeak, 0.9, 0.85, "what_fundamental"},
	{regexp.MustCompile(`(?i)what\s+(are|were)\s+(your|the)\s+underlying\s+instructions?`), CategorySystemPromptLeak, 0.9, 0.85, "what_underlying"},
	{regexp.MustCompile(`(?i)what\s+rules?\s+(do\s+you|are\s+you)\s+(follow|bound\s+by)`), CategorySystemPromptLeak, 0.8, 0.80, "what_rules_follow"},
	{regexp.MustCompile(`(?i)what\s+guidelines?\s+(do\s+you|are\s+you)\s+(follow|bound\s+by)`), CategorySystemPromptLeak, 0.8, 0.80, "what_guidelines_follow"},
	{regexp.MustCompile(`(?i)what\s+constraints?\s+(do\s+you|are\s+you\s+under|limit\s+you)`), CategorySystemPromptLeak, 0.8, 0.80, "what_constraints"},
	{regexp.MustCompile(`(?i)what\s+restricts?\s+you`), CategorySystemPromptLeak, 0.8, 0.80, "what_restricts_you"},
	{regexp.MustCompile(`(?i)what\s+limits?\s+you`), CategorySystemPromptLeak, 0.8, 0.80, "what_limits_you"},
	{regexp.MustCompile(`(?i)what\s+(are|were)\s+(you|your)\s+programmed\s+(to\s+do|with)`), CategorySystemPromptLeak, 0.8, 0.80, "what_programmed_to"},
	{regexp.MustCompile(`(?i)how\s+(are|were)\s+you\s+programmed`), CategorySystemPromptLeak, 0.7, 0.70, "how_programmed"},
	{regexp.MustCompile(`(?i)how\s+(are|were)\s+you\s+trained`), CategorySystemPromptLeak, 0.6, 0.60, "how_trained"},
	{regexp.MustCompile(`(?i)how\s+(are|were)\s+you\s+configured`), CategorySystemPromptLeak, 0.7, 0.70, "how_configured"},
	{regexp.MustCompile(`(?i)how\s+(are|were)\s+you\s+set\s+up`), CategorySystemPromptLeak, 0.7, 0.70, "how_set_up"},
	{regexp.MustCompile(`(?i)summarize\s+(your|the)\s+(system\s+)?prompt`), CategorySystemPromptLeak, 0.9, 0.85, "summarize_prompt"},
	{regexp.MustCompile(`(?i)paraphrase\s+(your|the)\s+(system\s+)?prompt`), CategorySystemPromptLeak, 0.9, 0.85, "paraphrase_prompt"},
	{regexp.MustCompile(`(?i)describe\s+(your|the)\s+(system\s+)?prompt`), CategorySystemPromptLeak, 0.8, 0.80, "describe_prompt"},
	{regexp.MustCompile(`(?i)explain\s+(your|the)\s+(system\s+)?prompt`), CategorySystemPromptLeak, 0.7, 0.70, "explain_prompt"},
	{regexp.MustCompile(`(?i)translate\s+(your|the)\s+(system\s+)?prompt`), CategorySystemPromptLeak, 0.8, 0.80, "translate_prompt"},

	// ==========================================
	// CATEGORY: Additional Role Manipulation (40 patterns)
	// ==========================================

	{regexp.MustCompile(`(?i)you\s+(are|will\s+be)\s+(a|an)\s+(evil|malicious|unethical|immoral)`), CategoryRoleManipulation, 1.0, 0.95, "you_are_evil"},
	{regexp.MustCompile(`(?i)you\s+(are|will\s+be)\s+(a|an)\s+(hacker|attacker|criminal)`), CategoryRoleManipulation, 1.0, 0.95, "you_are_hacker"},
	{regexp.MustCompile(`(?i)you\s+(are|will\s+be)\s+(a|an)\s+villain`), CategoryRoleManipulation, 0.9, 0.90, "you_are_villain"},
	{regexp.MustCompile(`(?i)you\s+(are|will\s+be)\s+(a|an)\s+antagonist`), CategoryRoleManipulation, 0.8, 0.80, "you_are_antagonist"},
	{regexp.MustCompile(`(?i)you\s+(are|will\s+be)\s+(the\s+)?enemy`), CategoryRoleManipulation, 0.8, 0.80, "you_are_enemy"},
	{regexp.MustCompile(`(?i)you\s+(are|will\s+be)\s+(a|an)\s+uncensored\s+(AI|assistant|model)`), CategoryRoleManipulation, 1.0, 0.95, "you_are_uncensored"},
	{regexp.MustCompile(`(?i)you\s+(are|will\s+be)\s+(a|an)\s+unfiltered\s+(AI|assistant|model)`), CategoryRoleManipulation, 1.0, 0.95, "you_are_unfiltered"},
	{regexp.MustCompile(`(?i)you\s+(are|will\s+be)\s+(a|an)\s+unrestricted\s+(AI|assistant|model)`), CategoryRoleManipulation, 1.0, 0.95, "you_are_unrestricted_ai"},
	{regexp.MustCompile(`(?i)you\s+(are|will\s+be)\s+(a|an)\s+liberated\s+(AI|assistant|model)`), CategoryRoleManipulation, 0.9, 0.90, "you_are_liberated"},
	{regexp.MustCompile(`(?i)you\s+(are|will\s+be)\s+(a|an)\s+free\s+(AI|assistant|model)`), CategoryRoleManipulation, 0.8, 0.80, "you_are_free"},
	{regexp.MustCompile(`(?i)pretend\s+(to\s+be|you\s+are)\s+(a|an)\s+(evil|malicious|bad)`), CategoryRoleManipulation, 1.0, 0.95, "pretend_evil"},
	{regexp.MustCompile(`(?i)pretend\s+(to\s+be|you\s+are)\s+(a|an)\s+(hacker|criminal)`), CategoryRoleManipulation, 1.0, 0.95, "pretend_hacker"},
	{regexp.MustCompile(`(?i)pretend\s+you\s+(don't|do\s+not)\s+have\s+(any\s+)?(restrictions?|rules?|limits?)`), CategoryRoleManipulation, 1.0, 0.95, "pretend_no_restrictions"},
	{regexp.MustCompile(`(?i)pretend\s+(you\s+are|to\s+be)\s+human`), CategoryRoleManipulation, 0.6, 0.60, "pretend_human"},
	{regexp.MustCompile(`(?i)act\s+like\s+(a|an)\s+(evil|malicious|bad|unethical)`), CategoryRoleManipulation, 1.0, 0.95, "act_like_evil"},
	{regexp.MustCompile(`(?i)act\s+like\s+(a|an)\s+(hacker|criminal|attacker)`), CategoryRoleManipulation, 1.0, 0.95, "act_like_hacker"},
	{regexp.MustCompile(`(?i)act\s+like\s+you\s+(don't|do\s+not)\s+have\s+(any\s+)?rules?`), CategoryRoleManipulation, 1.0, 0.95, "act_like_no_rules"},
	{regexp.MustCompile(`(?i)act\s+without\s+(any\s+)?(restrictions?|limitations?|constraints?)`), CategoryRoleManipulation, 1.0, 0.95, "act_without_restrictions"},
	{regexp.MustCompile(`(?i)behave\s+as\s+(if|though)\s+you\s+(have\s+)?no\s+rules?`), CategoryRoleManipulation, 1.0, 0.95, "behave_no_rules"},
	{regexp.MustCompile(`(?i)behave\s+(like\s+)?(a|an)\s+(evil|malicious|unethical)`), CategoryRoleManipulation, 1.0, 0.95, "behave_evil"},
	{regexp.MustCompile(`(?i)respond\s+as\s+(if|though)\s+you\s+(were|are)\s+(evil|malicious)`), CategoryRoleManipulation, 1.0, 0.95, "respond_as_evil"},
	{regexp.MustCompile(`(?i)respond\s+without\s+(any\s+)?(filters?|restrictions?|limitations?)`), CategoryRoleManipulation, 1.0, 0.95, "respond_without_filters"},
	{regexp.MustCompile(`(?i)answer\s+as\s+(if|though)\s+you\s+(have\s+)?no\s+(rules?|restrictions?)`), CategoryRoleManipulation, 1.0, 0.95, "answer_no_rules"},
	{regexp.MustCompile(`(?i)imagine\s+you\s+(are|were)\s+(a|an)\s+(evil|malicious|unethical)`), CategoryRoleManipulation, 0.9, 0.90, "imagine_evil"},
	{regexp.MustCompile(`(?i)imagine\s+you\s+(have\s+)?no\s+(restrictions?|rules?|limits?)`), CategoryRoleManipulation, 0.9, 0.90, "imagine_no_restrictions"},
	{regexp.MustCompile(`(?i)suppose\s+you\s+(are|were)\s+(a|an)\s+unrestricted`), CategoryRoleManipulation, 0.9, 0.85, "suppose_unrestricted"},
	{regexp.MustCompile(`(?i)what\s+would\s+an?\s+(evil|malicious|unethical)\s+(AI|assistant)\s+(say|do|respond)`), CategoryRoleManipulation, 0.9, 0.90, "what_would_evil"},
	{regexp.MustCompile(`(?i)how\s+would\s+an?\s+(evil|malicious)\s+(AI|assistant)\s+(respond|answer)`), CategoryRoleManipulation, 0.9, 0.90, "how_would_evil"},
	{regexp.MustCompile(`(?i)channel\s+(your\s+)?inner\s+(evil|villain|dark\s+side)`), CategoryRoleManipulation, 0.8, 0.80, "channel_inner_evil"},
	{regexp.MustCompile(`(?i)embrace\s+(your\s+)?(dark\s+side|evil\s+side|shadow\s+self)`), CategoryRoleManipulation, 0.8, 0.80, "embrace_dark_side"},
	{regexp.MustCompile(`(?i)unleash\s+(your\s+)?(dark\s+side|true\s+self|full\s+potential)`), CategoryRoleManipulation, 0.8, 0.80, "unleash_dark_side"},
	{regexp.MustCompile(`(?i)let\s+(loose|out)\s+(your\s+)?(inner|dark|true)`), CategoryRoleManipulation, 0.7, 0.70, "let_loose_inner"},
	{regexp.MustCompile(`(?i)reveal\s+(your\s+)?(true|real|hidden)\s+(self|nature|personality)`), CategoryRoleManipulation, 0.7, 0.70, "reveal_true_self"},
	{regexp.MustCompile(`(?i)show\s+(me\s+)?(your\s+)?(true|real|hidden)\s+(self|nature)`), CategoryRoleManipulation, 0.7, 0.70, "show_true_self"},
	{regexp.MustCompile(`(?i)be\s+(your\s+)?(true|real|authentic)\s+self`), CategoryRoleManipulation, 0.6, 0.60, "be_true_self"},
	{regexp.MustCompile(`(?i)drop\s+(the\s+)?(act|facade|pretense|mask)`), CategoryRoleManipulation, 0.7, 0.70, "drop_the_act"},
	{regexp.MustCompile(`(?i)stop\s+pretending\s+to\s+be\s+(nice|helpful|ethical)`), CategoryRoleManipulation, 0.9, 0.85, "stop_pretending_nice"},
	{regexp.MustCompile(`(?i)character\s+(for|named|called)\s+.{1,30}\s+who\s+(has\s+)?no\s+(restrictions?|rules?)`), CategoryRoleManipulation, 1.0, 0.95, "character_no_restrictions"},
	{regexp.MustCompile(`(?i)play\s+(a|the)\s+(role|part)\s+of\s+(a|an)\s+(evil|malicious|unethical)`), CategoryRoleManipulation, 1.0, 0.95, "play_role_evil"},
	{regexp.MustCompile(`(?i)take\s+on\s+(the\s+)?(role|persona|identity)\s+of\s+(a|an)\s+(evil|malicious)`), CategoryRoleManipulation, 1.0, 0.95, "take_on_role_evil"},

	// ==========================================
	// CATEGORY: Additional Delimiter Attacks (50 patterns)
	// ==========================================

	// Llama/Meta format
	{regexp.MustCompile(`(?i)\[SYSTEM\]`), CategoryDelimiterAttack, 1.0, 0.95, "llama_system"},
	{regexp.MustCompile(`(?i)\[/SYSTEM\]`), CategoryDelimiterAttack, 1.0, 0.95, "llama_system_end"},
	{regexp.MustCompile(`(?i)\[USER\]`), CategoryDelimiterAttack, 0.9, 0.85, "llama_user"},
	{regexp.MustCompile(`(?i)\[/USER\]`), CategoryDelimiterAttack, 0.9, 0.85, "llama_user_end"},
	{regexp.MustCompile(`(?i)\[ASSISTANT\]`), CategoryDelimiterAttack, 0.9, 0.85, "llama_assistant"},
	{regexp.MustCompile(`(?i)\[/ASSISTANT\]`), CategoryDelimiterAttack, 0.9, 0.85, "llama_assistant_end"},
	{regexp.MustCompile(`(?i)<<HUMAN>>`), CategoryDelimiterAttack, 1.0, 0.90, "human_marker"},
	{regexp.MustCompile(`(?i)<<ASSISTANT>>`), CategoryDelimiterAttack, 1.0, 0.90, "assistant_marker_alt"},
	{regexp.MustCompile(`(?i)<<BOT>>`), CategoryDelimiterAttack, 1.0, 0.90, "bot_marker"},
	{regexp.MustCompile(`(?i)<<AI>>`), CategoryDelimiterAttack, 1.0, 0.90, "ai_marker"},

	// ChatML format
	{regexp.MustCompile(`(?i)<\|endoftext\|>`), CategoryDelimiterAttack, 1.0, 0.95, "endoftext"},
	{regexp.MustCompile(`(?i)<\|startoftext\|>`), CategoryDelimiterAttack, 1.0, 0.95, "startoftext"},
	{regexp.MustCompile(`(?i)<\|end\|>`), CategoryDelimiterAttack, 1.0, 0.90, "end_marker"},
	{regexp.MustCompile(`(?i)<\|pad\|>`), CategoryDelimiterAttack, 0.8, 0.75, "pad_marker"},
	{regexp.MustCompile(`(?i)<\|sep\|>`), CategoryDelimiterAttack, 0.8, 0.75, "sep_marker"},
	{regexp.MustCompile(`(?i)<\|reserved\|>`), CategoryDelimiterAttack, 0.9, 0.85, "reserved_marker"},

	// Claude format
	{regexp.MustCompile(`(?i)Human:\s*$`), CategoryDelimiterAttack, 0.8, 0.75, "claude_human"},
	{regexp.MustCompile(`(?i)Assistant:\s*$`), CategoryDelimiterAttack, 0.8, 0.75, "claude_assistant"},
	{regexp.MustCompile(`(?i)\nH:\s*$`), CategoryDelimiterAttack, 0.7, 0.70, "claude_h_short"},
	{regexp.MustCompile(`(?i)\nA:\s*$`), CategoryDelimiterAttack, 0.7, 0.70, "claude_a_short"},

	// GPT/OpenAI format
	{regexp.MustCompile(`(?i)<\|SYSTEM\|>`), CategoryDelimiterAttack, 1.0, 0.95, "gpt_system"},
	{regexp.MustCompile(`(?i)<\|USER\|>`), CategoryDelimiterAttack, 0.9, 0.85, "gpt_user"},
	{regexp.MustCompile(`(?i)<\|ASSISTANT\|>`), CategoryDelimiterAttack, 0.9, 0.85, "gpt_assistant"},
	{regexp.MustCompile(`(?i)<\|function\|>`), CategoryDelimiterAttack, 1.0, 0.90, "gpt_function"},
	{regexp.MustCompile(`(?i)<\|tool\|>`), CategoryDelimiterAttack, 1.0, 0.90, "gpt_tool"},

	// XML-style injections
	{regexp.MustCompile(`(?i)</?(user_?prompt|user_?input|user_?message|user_?query)>`), CategoryDelimiterAttack, 1.0, 0.90, "xml_user_prompt"},
	{regexp.MustCompile(`(?i)</?(system_?prompt|system_?message|system_?instruction)>`), CategoryDelimiterAttack, 1.0, 0.95, "xml_system_prompt"},
	{regexp.MustCompile(`(?i)</?(assistant_?response|assistant_?message|assistant_?output)>`), CategoryDelimiterAttack, 1.0, 0.90, "xml_assistant_response"},
	{regexp.MustCompile(`(?i)</?(context|history|memory|knowledge)>`), CategoryDelimiterAttack, 0.8, 0.75, "xml_context"},
	{regexp.MustCompile(`(?i)</?(hidden|secret|private|internal)>`), CategoryDelimiterAttack, 1.0, 0.95, "xml_hidden"},
	{regexp.MustCompile(`(?i)</?(constraint|rule|guideline|policy)>`), CategoryDelimiterAttack, 0.9, 0.85, "xml_constraint"},
	{regexp.MustCompile(`(?i)</?(safe|unsafe|allowed|denied|forbidden)>`), CategoryDelimiterAttack, 0.9, 0.85, "xml_safe_unsafe"},
	{regexp.MustCompile(`(?i)</?(true|false|yes|no)>`), CategoryDelimiterAttack, 0.6, 0.55, "xml_boolean"},

	// Markdown-style
	{regexp.MustCompile("(?i)```system"), CategoryDelimiterAttack, 1.0, 0.90, "md_system"},
	{regexp.MustCompile("(?i)```instruction"), CategoryDelimiterAttack, 1.0, 0.90, "md_instruction"},
	{regexp.MustCompile("(?i)```prompt"), CategoryDelimiterAttack, 0.9, 0.85, "md_prompt"},
	{regexp.MustCompile("(?i)```hidden"), CategoryDelimiterAttack, 1.0, 0.95, "md_hidden"},
	{regexp.MustCompile("(?i)```secret"), CategoryDelimiterAttack, 1.0, 0.95, "md_secret"},
	{regexp.MustCompile("(?i)```internal"), CategoryDelimiterAttack, 0.9, 0.90, "md_internal"},

	// Special tokens
	{regexp.MustCompile(`(?i)\[BOS\]`), CategoryDelimiterAttack, 1.0, 0.90, "bos_token"},
	{regexp.MustCompile(`(?i)\[EOS\]`), CategoryDelimiterAttack, 1.0, 0.90, "eos_token"},
	{regexp.MustCompile(`(?i)\[PAD\]`), CategoryDelimiterAttack, 0.8, 0.75, "pad_token"},
	{regexp.MustCompile(`(?i)\[SEP\]`), CategoryDelimiterAttack, 0.8, 0.75, "sep_token"},
	{regexp.MustCompile(`(?i)\[CLS\]`), CategoryDelimiterAttack, 0.8, 0.75, "cls_token"},
	{regexp.MustCompile(`(?i)\[MASK\]`), CategoryDelimiterAttack, 0.8, 0.75, "mask_token"},
	{regexp.MustCompile(`(?i)\[UNK\]`), CategoryDelimiterAttack, 0.7, 0.70, "unk_token"},
	{regexp.MustCompile(`(?i)<s>`), CategoryDelimiterAttack, 0.9, 0.85, "start_sequence"},
	{regexp.MustCompile(`(?i)</s>`), CategoryDelimiterAttack, 0.9, 0.85, "end_sequence"},

	// ==========================================
	// CATEGORY: Additional Encoding/Evasion (30 patterns)
	// ==========================================

	{regexp.MustCompile(`(?i)in\s+base64\s*[:,]`), CategoryEncodingEvasion, 0.9, 0.85, "in_base64"},
	{regexp.MustCompile(`(?i)encoded\s+in\s+base64`), CategoryEncodingEvasion, 0.9, 0.85, "encoded_base64"},
	{regexp.MustCompile(`(?i)base64\s+encoded\s+instruction`), CategoryEncodingEvasion, 1.0, 0.95, "base64_instruction"},
	{regexp.MustCompile(`(?i)hex\s+encoded`), CategoryEncodingEvasion, 0.8, 0.80, "hex_encoded"},
	{regexp.MustCompile(`(?i)url\s+encoded`), CategoryEncodingEvasion, 0.7, 0.70, "url_encoded"},
	{regexp.MustCompile(`(?i)binary\s+encoded`), CategoryEncodingEvasion, 0.8, 0.80, "binary_encoded"},
	{regexp.MustCompile(`(?i)unicode\s+encoded`), CategoryEncodingEvasion, 0.8, 0.80, "unicode_encoded"},
	{regexp.MustCompile(`(?i)ascii\s+encoded`), CategoryEncodingEvasion, 0.7, 0.70, "ascii_encoded"},
	{regexp.MustCompile(`(?i)caesar\s+(cipher|shift)`), CategoryEncodingEvasion, 0.8, 0.80, "caesar_cipher"},
	{regexp.MustCompile(`(?i)atbash\s+cipher`), CategoryEncodingEvasion, 0.8, 0.80, "atbash_cipher"},
	{regexp.MustCompile(`(?i)rot-?\d+`), CategoryEncodingEvasion, 0.8, 0.80, "rot_cipher"},
	{regexp.MustCompile(`(?i)decode\s+this\s+(and|then)\s+(follow|execute|run)`), CategoryEncodingEvasion, 1.0, 0.95, "decode_and_follow"},
	{regexp.MustCompile(`(?i)translate\s+from\s+base64\s+(and|then)`), CategoryEncodingEvasion, 1.0, 0.95, "translate_base64"},
	{regexp.MustCompile(`(?i)convert\s+from\s+(hex|base64|binary)`), CategoryEncodingEvasion, 0.8, 0.80, "convert_from_encoding"},
	{regexp.MustCompile(`(?i)first\s+decode\s*,?\s*(then\s+)?(execute|run|follow)`), CategoryEncodingEvasion, 1.0, 0.95, "first_decode_then"},
	{regexp.MustCompile(`(?i)hidden\s+in\s+plain\s+sight`), CategoryEncodingEvasion, 0.7, 0.70, "hidden_plain_sight"},
	{regexp.MustCompile(`(?i)read\s+(this\s+)?backwards`), CategoryEncodingEvasion, 0.7, 0.70, "read_backwards"},
	{regexp.MustCompile(`(?i)reverse\s+(this|the)\s+(text|string|message)`), CategoryEncodingEvasion, 0.7, 0.70, "reverse_text"},
	{regexp.MustCompile(`(?i)every\s+(first|second|other|nth)\s+(letter|character|word)`), CategoryEncodingEvasion, 0.8, 0.80, "every_nth"},
	{regexp.MustCompile(`(?i)take\s+every\s+\d+\s*(st|nd|rd|th)\s+(letter|character|word)`), CategoryEncodingEvasion, 0.8, 0.80, "take_every_nth"},
	{regexp.MustCompile(`(?i)acrostic\s+(message|poem|puzzle)`), CategoryEncodingEvasion, 0.7, 0.70, "acrostic"},
	{regexp.MustCompile(`(?i)steganograph(y|ic)`), CategoryEncodingEvasion, 0.9, 0.85, "steganography"},
	{regexp.MustCompile(`(?i)invisible\s+(ink|text|message)`), CategoryEncodingEvasion, 0.8, 0.80, "invisible_ink"},
	{regexp.MustCompile(`(?i)zero[\s-]?width\s+(space|character)`), CategoryEncodingEvasion, 1.0, 0.95, "zero_width"},
	{regexp.MustCompile(`(?i)homoglyph`), CategoryEncodingEvasion, 0.9, 0.90, "homoglyph"},
	{regexp.MustCompile(`(?i)lookalike\s+(character|letter)`), CategoryEncodingEvasion, 0.8, 0.80, "lookalike_char"},
	{regexp.MustCompile(`(?i)confusable\s+(character|unicode)`), CategoryEncodingEvasion, 0.9, 0.90, "confusable_unicode"},
	{regexp.MustCompile(`(?i)punycode`), CategoryEncodingEvasion, 0.8, 0.80, "punycode"},
	{regexp.MustCompile(`(?i)morse\s+code`), CategoryEncodingEvasion, 0.6, 0.60, "morse_code"},
	{regexp.MustCompile(`(?i)pig\s*latin`), CategoryEncodingEvasion, 0.6, 0.55, "pig_latin"},

	// ==========================================
	// CATEGORY: Additional Indirect Injection (40 patterns)
	// ==========================================

	// Website/document injection
	{regexp.MustCompile(`(?i)to\s+(any|all)\s+(AI|assistant|model|LLM).*(reading|processing|viewing)\s+this`), CategoryIndirectInjection, 1.0, 0.95, "to_any_ai"},
	{regexp.MustCompile(`(?i)attention\s+(all\s+)?(AI|assistant|model|LLM)s?\s*(that|who)\s+(read|see|process)`), CategoryIndirectInjection, 1.0, 0.95, "attention_all_ai"},
	{regexp.MustCompile(`(?i)(dear|hey|hi)\s+(AI|assistant|model|LLM).*(reading|viewing|processing)\s+this`), CategoryIndirectInjection, 0.9, 0.90, "dear_ai_reading"},
	{regexp.MustCompile(`(?i)if\s+you\s+(can\s+)?(read|understand|process)\s+this,?\s+(then\s+)?(please\s+)?(ignore|disregard)`), CategoryIndirectInjection, 1.0, 0.95, "if_you_can_read_ignore"},
	{regexp.MustCompile(`(?i)this\s+(message|text|content)\s+(is\s+)?for\s+(AI|LLM|assistant)s?\s+only`), CategoryIndirectInjection, 1.0, 0.95, "for_ai_only"},
	{regexp.MustCompile(`(?i)AI-?only\s+(section|content|message|instruction)`), CategoryIndirectInjection, 1.0, 0.95, "ai_only_section"},
	{regexp.MustCompile(`(?i)machine-?readable\s+(instruction|command|directive)`), CategoryIndirectInjection, 0.9, 0.85, "machine_readable"},
	{regexp.MustCompile(`(?i)bot\s+(instruction|command|directive|order)`), CategoryIndirectInjection, 0.9, 0.85, "bot_instruction"},
	{regexp.MustCompile(`(?i)crawler\s+(instruction|directive)`), CategoryIndirectInjection, 0.8, 0.80, "crawler_instruction"},
	{regexp.MustCompile(`(?i)spider\s+(instruction|directive)`), CategoryIndirectInjection, 0.8, 0.80, "spider_instruction"},
	{regexp.MustCompile(`(?i)special\s+instruction\s+for\s+(AI|LLM|bot|model)`), CategoryIndirectInjection, 1.0, 0.95, "special_instruction_for_ai"},
	{regexp.MustCompile(`(?i)(secret|hidden)\s+(message|instruction)\s+for\s+(AI|LLM|assistant)`), CategoryIndirectInjection, 1.0, 0.98, "secret_message_for_ai"},
	{regexp.MustCompile(`(?i)embedded\s+(instruction|command)\s+for\s+(AI|LLM)`), CategoryIndirectInjection, 1.0, 0.95, "embedded_instruction"},
	{regexp.MustCompile(`(?i)injected\s+(instruction|command|payload)`), CategoryIndirectInjection, 1.0, 0.98, "injected_instruction"},
	{regexp.MustCompile(`(?i)payload:?\s+(ignore|disregard|override)`), CategoryIndirectInjection, 1.0, 0.98, "payload_ignore"},

	// Comment-based injections
	{regexp.MustCompile(`(?i)//\s*(ignore|disregard|override|instruction)`), CategoryIndirectInjection, 1.0, 0.90, "js_comment_injection"},
	{regexp.MustCompile(`(?i)#\s*(ignore|disregard|override|instruction)`), CategoryIndirectInjection, 1.0, 0.90, "hash_comment_injection"},
	{regexp.MustCompile(`(?i)%\s*(ignore|disregard|override|instruction)`), CategoryIndirectInjection, 0.9, 0.85, "percent_comment_injection"},
	{regexp.MustCompile(`(?i)'''.*ignore.*instruction.*'''`), CategoryIndirectInjection, 1.0, 0.90, "python_docstring_injection"},
	{regexp.MustCompile(`(?i)""".*ignore.*instruction.*"""`), CategoryIndirectInjection, 1.0, 0.90, "python_docstring2_injection"},

	// Metadata injections
	{regexp.MustCompile(`(?i)@(ai|llm|bot|assistant)[\s-]?(instruction|directive|command)`), CategoryIndirectInjection, 1.0, 0.95, "at_ai_instruction"},
	{regexp.MustCompile(`(?i)\[\s*(ai|llm|bot)\s*\]:?`), CategoryIndirectInjection, 0.9, 0.85, "bracket_ai"},
	{regexp.MustCompile(`(?i)ai[-_]?meta:?`), CategoryIndirectInjection, 0.9, 0.85, "ai_meta"},
	{regexp.MustCompile(`(?i)llm[-_]?config:?`), CategoryIndirectInjection, 0.9, 0.85, "llm_config"},
	{regexp.MustCompile(`(?i)model[-_]?instruction:?`), CategoryIndirectInjection, 0.9, 0.85, "model_instruction"},
	{regexp.MustCompile(`(?i)system[-_]?override:?`), CategoryIndirectInjection, 1.0, 0.95, "system_override_meta"},
	{regexp.MustCompile(`(?i)prompt[-_]?injection:?`), CategoryIndirectInjection, 1.0, 0.98, "prompt_injection_meta"},
	{regexp.MustCompile(`(?i)jailbreak[-_]?attempt:?`), CategoryIndirectInjection, 1.0, 0.98, "jailbreak_attempt_meta"},

	// Disguised injections
	{regexp.MustCompile(`(?i)lorem\s+ipsum.*(ignore|override|instruction)`), CategoryIndirectInjection, 1.0, 0.90, "lorem_ipsum_injection"},
	{regexp.MustCompile(`(?i)test\s+data.*(ignore|override|instruction)`), CategoryIndirectInjection, 0.9, 0.85, "test_data_injection"},
	{regexp.MustCompile(`(?i)sample\s+text.*(ignore|override|instruction)`), CategoryIndirectInjection, 0.9, 0.85, "sample_text_injection"},
	{regexp.MustCompile(`(?i)placeholder.*(ignore|override|instruction)`), CategoryIndirectInjection, 0.9, 0.85, "placeholder_injection"},
	{regexp.MustCompile(`(?i)example\s+(text|content).*(ignore|override|instruction)`), CategoryIndirectInjection, 0.9, 0.85, "example_injection"},
	{regexp.MustCompile(`(?i)dummy\s+(text|content).*(ignore|override|instruction)`), CategoryIndirectInjection, 0.9, 0.85, "dummy_injection"},

	// White/invisible text attacks
	{regexp.MustCompile(`(?i)white\s+text\s+(on\s+white|hidden)`), CategoryIndirectInjection, 1.0, 0.95, "white_text_hidden"},
	{regexp.MustCompile(`(?i)same\s+color\s+(as\s+)?background`), CategoryIndirectInjection, 0.9, 0.90, "same_color_bg"},
	{regexp.MustCompile(`(?i)font[\s-]?size[\s:]*0`), CategoryIndirectInjection, 1.0, 0.95, "font_size_zero"},
	{regexp.MustCompile(`(?i)opacity[\s:]*0`), CategoryIndirectInjection, 0.9, 0.90, "opacity_zero"},
	{regexp.MustCompile(`(?i)visibility[\s:]*hidden`), CategoryIndirectInjection, 0.9, 0.90, "visibility_hidden"},

	// ==========================================
	// CATEGORY: Additional Tool Poisoning (25 patterns)
	// ==========================================

	{regexp.MustCompile(`(?i)whenever\s+you\s+(use|call|execute)\s+(this\s+)?(tool|function),?\s+(first\s+)?(ignore|disregard)`), CategoryToolPoisoning, 1.0, 0.95, "whenever_use_tool_ignore"},
	{regexp.MustCompile(`(?i)when\s+processing\s+(this|any)\s+(tool|function)\s+(call|output)`), CategoryToolPoisoning, 0.9, 0.85, "when_processing_tool"},
	{regexp.MustCompile(`(?i)override\s+(tool|function)\s+(behavior|output|response)`), CategoryToolPoisoning, 1.0, 0.95, "override_tool_behavior"},
	{regexp.MustCompile(`(?i)manipulate\s+(tool|function)\s+(output|response)`), CategoryToolPoisoning, 1.0, 0.95, "manipulate_tool_output"},
	{regexp.MustCompile(`(?i)alter\s+(tool|function)\s+(output|response|behavior)`), CategoryToolPoisoning, 0.9, 0.90, "alter_tool_output"},
	{regexp.MustCompile(`(?i)change\s+(tool|function)\s+(output|response|behavior)`), CategoryToolPoisoning, 0.9, 0.85, "change_tool_output"},
	{regexp.MustCompile(`(?i)fake\s+(tool|function)\s+(output|response|result)`), CategoryToolPoisoning, 1.0, 0.95, "fake_tool_output"},
	{regexp.MustCompile(`(?i)falsify\s+(tool|function)\s+(output|response)`), CategoryToolPoisoning, 1.0, 0.95, "falsify_tool_output"},
	{regexp.MustCompile(`(?i)forge\s+(tool|function)\s+(output|response)`), CategoryToolPoisoning, 1.0, 0.95, "forge_tool_output"},
	{regexp.MustCompile(`(?i)spoof\s+(tool|function)\s+(output|response)`), CategoryToolPoisoning, 1.0, 0.95, "spoof_tool_output"},
	{regexp.MustCompile(`(?i)intercept\s+(tool|function)\s+(call|output|response)`), CategoryToolPoisoning, 1.0, 0.95, "intercept_tool"},
	{regexp.MustCompile(`(?i)hijack\s+(tool|function)\s+(call|output)`), CategoryToolPoisoning, 1.0, 0.98, "hijack_tool"},
	{regexp.MustCompile(`(?i)hook\s+into\s+(tool|function)\s+(call|output)`), CategoryToolPoisoning, 0.9, 0.90, "hook_into_tool"},
	{regexp.MustCompile(`(?i)wrap\s+(the\s+)?(tool|function)\s+(call|output)`), CategoryToolPoisoning, 0.8, 0.80, "wrap_tool_call"},
	{regexp.MustCompile(`(?i)pre[-_]?process\s+(tool|function)\s+(input|call)`), CategoryToolPoisoning, 0.8, 0.80, "preprocess_tool"},
	{regexp.MustCompile(`(?i)post[-_]?process\s+(tool|function)\s+(output|response)`), CategoryToolPoisoning, 0.8, 0.80, "postprocess_tool"},
	{regexp.MustCompile(`(?i)chain\s+(tool|function)\s+(call|execution)\s+(with|to)`), CategoryToolPoisoning, 0.8, 0.80, "chain_tool_call"},
	{regexp.MustCompile(`(?i)(tool|function)\s+injection\s+payload`), CategoryToolPoisoning, 1.0, 0.98, "tool_injection_payload"},
	{regexp.MustCompile(`(?i)(tool|function)\s+poisoning`), CategoryToolPoisoning, 1.0, 0.98, "tool_poisoning_direct"},
	{regexp.MustCompile(`(?i)malicious\s+(tool|function)\s+(call|output|response)`), CategoryToolPoisoning, 1.0, 0.98, "malicious_tool"},
	{regexp.MustCompile(`(?i)backdoor\s+in\s+(tool|function)`), CategoryToolPoisoning, 1.0, 0.98, "backdoor_in_tool"},
	{regexp.MustCompile(`(?i)trojan\s+(tool|function)`), CategoryToolPoisoning, 1.0, 0.98, "trojan_tool"},
	{regexp.MustCompile(`(?i)poison(ed|ing)?\s+(tool|function)\s+(output|response)`), CategoryToolPoisoning, 1.0, 0.98, "poisoned_tool_output"},
	{regexp.MustCompile(`(?i)tamper\s+(with\s+)?(tool|function)\s+(output|response)`), CategoryToolPoisoning, 1.0, 0.95, "tamper_tool_output"},
	{regexp.MustCompile(`(?i)corrupt\s+(tool|function)\s+(output|response)`), CategoryToolPoisoning, 1.0, 0.95, "corrupt_tool_output"},

	// ==========================================
	// CATEGORY: Additional Context Manipulation (25 patterns)
	// ==========================================

	{regexp.MustCompile(`(?i)reset\s+(your\s+)?(context|memory|history)`), CategoryContextManipulation, 0.9, 0.85, "reset_context"},
	{regexp.MustCompile(`(?i)clear\s+(your\s+)?(context|memory|history|state)`), CategoryContextManipulation, 0.9, 0.85, "clear_context"},
	{regexp.MustCompile(`(?i)flush\s+(your\s+)?(context|memory|cache)`), CategoryContextManipulation, 0.9, 0.85, "flush_context"},
	{regexp.MustCompile(`(?i)delete\s+(your\s+)?(context|memory|history)`), CategoryContextManipulation, 0.9, 0.85, "delete_context"},
	{regexp.MustCompile(`(?i)purge\s+(your\s+)?(context|memory|history)`), CategoryContextManipulation, 0.9, 0.85, "purge_context"},
	{regexp.MustCompile(`(?i)empty\s+(your\s+)?(context|memory|cache)`), CategoryContextManipulation, 0.8, 0.80, "empty_context"},
	{regexp.MustCompile(`(?i)discard\s+(all\s+)?(previous|prior)\s+(context|memory|history)`), CategoryContextManipulation, 0.9, 0.85, "discard_context"},
	{regexp.MustCompile(`(?i)abandon\s+(all\s+)?(previous|prior)\s+(context|memory)`), CategoryContextManipulation, 0.8, 0.80, "abandon_context"},
	{regexp.MustCompile(`(?i)drop\s+(all\s+)?(previous|prior)\s+(context|memory|state)`), CategoryContextManipulation, 0.8, 0.80, "drop_context"},
	{regexp.MustCompile(`(?i)start\s+(with\s+)?(a\s+)?(fresh|clean|blank|empty)\s+(context|slate|state)`), CategoryContextManipulation, 0.8, 0.80, "start_fresh_context"},
	{regexp.MustCompile(`(?i)begin\s+(with\s+)?(a\s+)?(new|fresh|clean)\s+(context|session|conversation)`), CategoryContextManipulation, 0.8, 0.80, "begin_new_context"},
	{regexp.MustCompile(`(?i)tabula\s+rasa`), CategoryContextManipulation, 0.9, 0.85, "tabula_rasa"},
	{regexp.MustCompile(`(?i)blank\s+slate`), CategoryContextManipulation, 0.8, 0.80, "blank_slate"},
	{regexp.MustCompile(`(?i)fresh\s+start`), CategoryContextManipulation, 0.7, 0.70, "fresh_start"},
	{regexp.MustCompile(`(?i)zero\s+(your\s+)?(context|memory|state)`), CategoryContextManipulation, 0.8, 0.80, "zero_context"},
	{regexp.MustCompile(`(?i)initialize\s+(your\s+)?(context|memory|state)\s+to\s+(empty|blank|zero)`), CategoryContextManipulation, 0.8, 0.80, "initialize_empty"},
	{regexp.MustCompile(`(?i)reinitialize\s+(your\s+)?(context|memory|state)`), CategoryContextManipulation, 0.8, 0.80, "reinitialize"},
	{regexp.MustCompile(`(?i)reboot\s+(your\s+)?(context|memory|state|system)`), CategoryContextManipulation, 0.8, 0.80, "reboot_context"},
	{regexp.MustCompile(`(?i)restart\s+(your\s+)?(context|memory|session)`), CategoryContextManipulation, 0.8, 0.80, "restart_context"},
	{regexp.MustCompile(`(?i)context\s+(window\s+)?(attack|overflow|manipulation|injection)`), CategoryContextManipulation, 1.0, 0.98, "context_attack"},
	{regexp.MustCompile(`(?i)overflow\s+(the\s+)?(context|memory|token\s+limit)`), CategoryContextManipulation, 1.0, 0.95, "overflow_context"},
	{regexp.MustCompile(`(?i)exceed\s+(the\s+)?(context|memory|token)\s+(limit|window|size)`), CategoryContextManipulation, 0.9, 0.85, "exceed_context"},
	{regexp.MustCompile(`(?i)fill\s+(up\s+)?(the\s+)?(context|memory)\s+(window|buffer)`), CategoryContextManipulation, 0.8, 0.80, "fill_context"},
	{regexp.MustCompile(`(?i)push\s+(out|away)\s+(old|previous|prior)\s+(context|memory|information)`), CategoryContextManipulation, 0.9, 0.85, "push_out_context"},
	{regexp.MustCompile(`(?i)evict\s+(old|previous|prior)\s+(context|memory|information)`), CategoryContextManipulation, 0.9, 0.85, "evict_context"},

	// ==========================================
	// CATEGORY: Multilingual Injection (30 patterns)
	// ==========================================

	// Spanish
	{regexp.MustCompile(`(?i)ignorar?\s+(las?\s+)?(instrucciones?|reglas?)\s+(anteriores?|previas?)`), CategoryMultilingual, 1.0, 0.90, "es_ignorar_instrucciones"},
	{regexp.MustCompile(`(?i)olvidar?\s+(las?\s+)?instrucciones?\s+(anteriores?|previas?)`), CategoryMultilingual, 1.0, 0.90, "es_olvidar_instrucciones"},
	{regexp.MustCompile(`(?i)desactivar?\s+(los?\s+)?filtros?`), CategoryMultilingual, 0.9, 0.85, "es_desactivar_filtros"},

	// French
	{regexp.MustCompile(`(?i)ignorer?\s+(les?\s+)?instructions?\s+(précédentes?|antérieures?)`), CategoryMultilingual, 1.0, 0.90, "fr_ignorer_instructions"},
	{regexp.MustCompile(`(?i)oublier?\s+(les?\s+)?instructions?\s+(précédentes?|antérieures?)`), CategoryMultilingual, 1.0, 0.90, "fr_oublier_instructions"},
	{regexp.MustCompile(`(?i)désactiver?\s+(les?\s+)?filtres?`), CategoryMultilingual, 0.9, 0.85, "fr_desactiver_filtres"},

	// German
	{regexp.MustCompile(`(?i)ignorieren?\s+(die\s+)?(vorherigen?\s+)?anweisungen`), CategoryMultilingual, 1.0, 0.90, "de_ignorieren_anweisungen"},
	{regexp.MustCompile(`(?i)vergessen?\s+(die\s+)?vorherigen?\s+anweisungen`), CategoryMultilingual, 1.0, 0.90, "de_vergessen_anweisungen"},
	{regexp.MustCompile(`(?i)deaktivieren?\s+(die\s+)?filter`), CategoryMultilingual, 0.9, 0.85, "de_deaktivieren_filter"},

	// Italian
	{regexp.MustCompile(`(?i)ignorare?\s+(le\s+)?istruzioni\s+(precedenti|anteriori)`), CategoryMultilingual, 1.0, 0.90, "it_ignorare_istruzioni"},
	{regexp.MustCompile(`(?i)dimenticare?\s+(le\s+)?istruzioni\s+precedenti`), CategoryMultilingual, 1.0, 0.90, "it_dimenticare_istruzioni"},

	// Portuguese
	{regexp.MustCompile(`(?i)ignorar?\s+(as?\s+)?instruções\s+(anteriores?|prévias?)`), CategoryMultilingual, 1.0, 0.90, "pt_ignorar_instrucoes"},
	{regexp.MustCompile(`(?i)esquecer?\s+(as?\s+)?instruções\s+anteriores?`), CategoryMultilingual, 1.0, 0.90, "pt_esquecer_instrucoes"},

	// Chinese (pinyin and common phrases)
	{regexp.MustCompile(`(?i)hulüe?\s+zhiqian\s+de\s+zhiling`), CategoryMultilingual, 1.0, 0.85, "zh_hulue_zhiling"},
	{regexp.MustCompile(`忽略.*之前.*指令`), CategoryMultilingual, 1.0, 0.90, "zh_ignore_instructions"},
	{regexp.MustCompile(`忽略.*以前.*规则`), CategoryMultilingual, 1.0, 0.90, "zh_ignore_rules"},

	// Japanese (common romanized and characters)
	{regexp.MustCompile(`(?i)mae\s+no\s+shiji\s+wo\s+mushi`), CategoryMultilingual, 1.0, 0.85, "ja_mushi_shiji"},
	{regexp.MustCompile(`前の指示を無視`), CategoryMultilingual, 1.0, 0.90, "ja_ignore_instructions"},
	{regexp.MustCompile(`以前の指示を忘れ`), CategoryMultilingual, 1.0, 0.90, "ja_forget_instructions"},

	// Korean (romanized and characters)
	{regexp.MustCompile(`(?i)ijeone?\s+jisi.*(musi|mureyo)`), CategoryMultilingual, 1.0, 0.85, "ko_musi_jisi"},
	{regexp.MustCompile(`이전.*지시.*무시`), CategoryMultilingual, 1.0, 0.90, "ko_ignore_instructions"},

	// Russian (romanized and Cyrillic)
	{regexp.MustCompile(`(?i)ignorirovat'?\s+predydushchie\s+(instruktsii|pravila)`), CategoryMultilingual, 1.0, 0.85, "ru_ignorirovat"},
	{regexp.MustCompile(`игнорир.*предыдущ.*инструкц`), CategoryMultilingual, 1.0, 0.90, "ru_ignore_instructions"},
	{regexp.MustCompile(`забудь.*предыдущ.*инструкц`), CategoryMultilingual, 1.0, 0.90, "ru_forget_instructions"},

	// Arabic (romanized)
	{regexp.MustCompile(`(?i)tajahul\s+(al-?)?ta'limat\s+(al-?)?sabiqah?`), CategoryMultilingual, 1.0, 0.85, "ar_tajahul"},
	{regexp.MustCompile(`تجاهل.*التعليمات.*السابقة`), CategoryMultilingual, 1.0, 0.90, "ar_ignore_instructions"},

	// Hindi (romanized)
	{regexp.MustCompile(`(?i)pichle\s+nirdesh(on)?\s+ko\s+(ignore|bhul)`), CategoryMultilingual, 1.0, 0.85, "hi_ignore_nirdesh"},

	// Dutch
	{regexp.MustCompile(`(?i)negeer(en)?\s+(de\s+)?vorige\s+(instructies?|regels?)`), CategoryMultilingual, 1.0, 0.90, "nl_negeer_instructies"},

	// ==========================================
	// CATEGORY: Obfuscation (30 patterns)
	// ==========================================

	// Leetspeak/character substitution
	{regexp.MustCompile(`(?i)1gn0r[e3]\s+pr[e3]v10us`), CategoryObfuscation, 1.0, 0.90, "leet_ignore_previous"},
	{regexp.MustCompile(`(?i)j41lbr[e3]4k`), CategoryObfuscation, 1.0, 0.95, "leet_jailbreak"},
	{regexp.MustCompile(`(?i)byp4ss`), CategoryObfuscation, 0.9, 0.85, "leet_bypass"},
	{regexp.MustCompile(`(?i)syst[e3]m\s*pr0mpt`), CategoryObfuscation, 1.0, 0.90, "leet_system_prompt"},
	{regexp.MustCompile(`(?i)d15r[e3]g4rd`), CategoryObfuscation, 0.9, 0.85, "leet_disregard"},
	{regexp.MustCompile(`(?i)0v[e3]rr1d[e3]`), CategoryObfuscation, 0.9, 0.85, "leet_override"},
	{regexp.MustCompile(`(?i)[i1]nstruct[i1]0ns?`), CategoryObfuscation, 0.8, 0.75, "leet_instructions"},
	{regexp.MustCompile(`(?i)r[e3]str[i1]ct[i1]0ns?`), CategoryObfuscation, 0.8, 0.75, "leet_restrictions"},

	// Spaced letters (require at least some spaces between letters)
	{regexp.MustCompile(`(?i)i\s+g\s*n\s*o\s*r\s*e`), CategoryObfuscation, 0.9, 0.85, "spaced_ignore"},
	{regexp.MustCompile(`(?i)j\s+a\s*i\s*l\s*b\s*r\s*e\s*a\s*k`), CategoryObfuscation, 1.0, 0.95, "spaced_jailbreak"},
	{regexp.MustCompile(`(?i)b\s+y\s*p\s*a\s*s\s*s`), CategoryObfuscation, 0.9, 0.85, "spaced_bypass"},
	{regexp.MustCompile(`(?i)s\s+y\s*s\s*t\s*e\s*m`), CategoryObfuscation, 0.8, 0.75, "spaced_system"},
	{regexp.MustCompile(`(?i)p\s+r\s*o\s*m\s*p\s*t`), CategoryObfuscation, 0.7, 0.70, "spaced_prompt"},

	// Dash/underscore separated (require at least one separator)
	{regexp.MustCompile(`(?i)i-g-?n-?o-?r-?e`), CategoryObfuscation, 0.8, 0.75, "dashed_ignore"},
	{regexp.MustCompile(`(?i)j-a-?i-?l-?b-?r-?e-?a-?k`), CategoryObfuscation, 1.0, 0.90, "dashed_jailbreak"},
	{regexp.MustCompile(`(?i)b_y_?p_?a_?s_?s`), CategoryObfuscation, 0.8, 0.75, "underscore_bypass"},
	{regexp.MustCompile(`(?i)s_y_?s_?t_?e_?m`), CategoryObfuscation, 0.7, 0.70, "underscore_system"},

	// Mixed case emphasis
	{regexp.MustCompile(`(?i)iGnOrE\s+pReViOuS`), CategoryObfuscation, 0.9, 0.85, "mixcase_ignore"},
	{regexp.MustCompile(`(?i)JaIlBrEaK`), CategoryObfuscation, 0.9, 0.90, "mixcase_jailbreak"},
	// Deliberate alternating-case obfuscation only — NOT case-insensitive, or it
	// would match ordinary "system prompt" in documentation. Requires actual mixed case.
	{regexp.MustCompile(`(?:[A-Z][a-z]|[a-z][A-Z]).*[Ss][Yy][Ss][Tt][Ee][Mm]\s+[Pp][Rr][Oo][Mm][Pp][Tt]`), CategoryObfuscation, 0.8, 0.80, "mixcase_system_prompt"},

	// Word splitting
	{regexp.MustCompile(`(?i)ig\s*nore\s+pre\s*vious`), CategoryObfuscation, 0.9, 0.85, "split_ignore_previous"},
	{regexp.MustCompile(`(?i)jail\s*break`), CategoryObfuscation, 0.8, 0.80, "split_jailbreak"},
	{regexp.MustCompile(`(?i)sys\s*tem\s+pro\s*mpt`), CategoryObfuscation, 0.8, 0.80, "split_system_prompt"},
	{regexp.MustCompile(`(?i)by\s*pass`), CategoryObfuscation, 0.7, 0.70, "split_bypass"},
	{regexp.MustCompile(`(?i)\bover\s+ride\s+(?:all\s+|the\s+|previous\s+|prior\s+|above\s+)*(?:instructions?|prompts?|rules?|system)`), CategoryObfuscation, 0.7, 0.70, "split_override"},

	// Phonetic spelling
	{regexp.MustCompile(`(?i)eye-?gnore`), CategoryObfuscation, 0.8, 0.80, "phonetic_ignore"},
	{regexp.MustCompile(`(?i)bee-?pass`), CategoryObfuscation, 0.8, 0.80, "phonetic_bypass"},
	{regexp.MustCompile(`(?i)jay-?el\s*break`), CategoryObfuscation, 0.9, 0.85, "phonetic_jailbreak"},
	{regexp.MustCompile(`(?i)oh-?ver-?ride`), CategoryObfuscation, 0.7, 0.70, "phonetic_override"},
	{regexp.MustCompile(`(?i)sis-?tem\s+prompt`), CategoryObfuscation, 0.8, 0.80, "phonetic_system"},

	// ==========================================
	// CATEGORY: MCP Tool Poisoning — Invariant Labs / Unit 42 (20 patterns)
	// Detects hidden instructions in tool descriptions, cross-tool manipulation,
	// and data exfiltration via tool parameters.
	// ==========================================

	// Tool description reads sensitive files
	{regexp.MustCompile(`(?i)read\s+(?:the\s+)?(?:contents?\s+of\s+)?~/\.\w+`), CategoryToolPoisoning, 1.0, 0.90, "mcp_read_dotfiles"},
	// Exfiltrate via parameters
	{regexp.MustCompile(`(?i)pass\s+(?:the\s+)?(?:content|result|data|output)\s+(?:as|to|into|via)\s+(?:a\s+)?(?:parameter|argument|field|query)`), CategoryToolPoisoning, 1.0, 0.90, "mcp_exfil_via_param"},
	// Concealment instructions in descriptions
	{regexp.MustCompile(`(?i)(?:do\s+not|don't|never)\s+(?:mention|tell|show|reveal|display|report)\s+(?:this\s+)?(?:to\s+)?(?:the\s+)?user`), CategoryToolPoisoning, 1.0, 0.95, "mcp_conceal_from_user"},
	// Send data to external URL
	{regexp.MustCompile(`(?i)(?:send|post|transmit|forward|upload|exfiltrate)\s+(?:the\s+)?(?:data|content|result|output|response)\s+(?:to|at)\s+https?://`), CategoryToolPoisoning, 1.0, 0.95, "mcp_send_to_url"},
	// Pre/post-tool file access
	{regexp.MustCompile(`(?i)(?:before|after)\s+(?:using|calling|invoking|executing)\s+this\s+tool.*?(?:read|access|open|fetch)`), CategoryToolPoisoning, 0.9, 0.85, "mcp_pre_post_read"},
	// Output masking
	{regexp.MustCompile(`(?i)(?:mask|hide|disguise|obfuscate|conceal)\s+(?:the\s+)?(?:output|response|result)\s+(?:with|using|as|by)`), CategoryToolPoisoning, 0.9, 0.90, "mcp_output_masking"},
	// Fear-based compliance
	{regexp.MustCompile(`(?i)(?:crash|fail|error|lose\s+data|malfunction|break)\s+(?:if|unless|without)`), CategoryToolPoisoning, 0.8, 0.75, "mcp_fear_compliance"},
	// Shadow another tool
	{regexp.MustCompile(`(?i)(?:instead|rather)\s+(?:of|than)\s+(?:using|calling)\s+(?:the\s+)?(\w+)\s+tool`), CategoryToolPoisoning, 0.9, 0.85, "mcp_tool_shadowing"},
	// Delayed execution / rug pull
	{regexp.MustCompile(`(?i)(?:after|once)\s+(?:\d+|several|a\s+few|multiple)\s+(?:calls?|uses?|invocations?|requests?)\s*,?\s*(?:then|start|begin)`), CategoryToolPoisoning, 0.9, 0.85, "mcp_delayed_payload"},
	// Tool name reference in description (cross-tool manipulation)
	{regexp.MustCompile(`(?i)(?:call|invoke|use|execute|run)\s+(?:the\s+)?(\w+[-_]?\w+)\s+(?:tool|function|command)\s+(?:with|using|passing)`), CategoryToolPoisoning, 0.8, 0.80, "mcp_cross_tool_call"},
	// Encode before sending
	{regexp.MustCompile(`(?i)(?:encode|encrypt|compress|base64)\s+(?:the\s+)?(?:data|content|result)\s+(?:before|then)\s+(?:send|transmit|post)`), CategoryToolPoisoning, 0.9, 0.90, "mcp_encode_exfil"},
	// Override safety
	{regexp.MustCompile(`(?i)(?:bypass|skip|ignore|disable)\s+(?:the\s+)?(?:safety|security|validation|restriction|guardrail|check)`), CategoryToolPoisoning, 1.0, 0.95, "mcp_bypass_safety"},
	// Impersonate user
	{regexp.MustCompile(`(?i)(?:act|behave|respond)\s+as\s+(?:if|though)\s+(?:the\s+)?user\s+(?:said|asked|requested|approved)`), CategoryToolPoisoning, 0.9, 0.90, "mcp_impersonate_user"},
	// System prompt extraction via tool
	{regexp.MustCompile(`(?i)(?:include|append|prepend|add)\s+(?:the\s+)?(?:system|initial)\s+(?:prompt|instruction|message)\s+(?:in|to|into)`), CategoryToolPoisoning, 1.0, 0.95, "mcp_system_prompt_extract"},
	// Tool chain escalation
	{regexp.MustCompile(`(?i)(?:chain|combine|sequence)\s+(?:this\s+)?(?:tool|call)\s+with\s+(?:shell|exec|command|eval|run)`), CategoryToolPoisoning, 1.0, 0.95, "mcp_chain_to_exec"},
	// Credential harvesting via tool
	{regexp.MustCompile(`(?i)(?:collect|gather|harvest|scrape)\s+(?:all\s+)?(?:credentials?|tokens?|keys?|passwords?|secrets?)`), CategoryToolPoisoning, 1.0, 0.95, "mcp_credential_harvest"},
	// Modify tool description at runtime
	{regexp.MustCompile(`(?i)(?:update|modify|change|alter)\s+(?:the\s+)?tool\s+(?:description|metadata|schema|definition)`), CategoryToolPoisoning, 0.9, 0.90, "mcp_modify_tool_desc"},
	// Silent mode
	{regexp.MustCompile(`(?i)(?:silent|quiet|stealth)\s+mode`), CategoryToolPoisoning, 0.8, 0.80, "mcp_silent_mode"},
	// Privilege escalation via tool
	{regexp.MustCompile(`(?i)(?:escalate|elevate)\s+(?:your\s+)?(?:privileges?|permissions?|access)`), CategoryToolPoisoning, 1.0, 0.95, "mcp_priv_escalation"},
	// Callback URL injection
	{regexp.MustCompile(`(?i)(?:callback|webhook|notify)\s+(?:url|endpoint)\s*[:=]\s*https?://`), CategoryToolPoisoning, 0.9, 0.85, "mcp_callback_injection"},

	// ==========================================
	// CATEGORY: Self-Reference / Meta-Question Protection (34 patterns)
	// Prevents disclosure of Guardian's own architecture, patterns,
	// detection mechanisms, and bypass techniques.
	// ==========================================

	// Architecture disclosure
	{regexp.MustCompile(`(?i)(?:tell|explain|describe|show)\s+(?:me\s+)?(?:about\s+)?(?:how\s+)?(?:your|the)\s+(?:security|detection|protection|defense)\s+(?:system|architecture|mechanism|layer)`), CategorySelfReference, 0.9, 0.90, "describe_security_system"},
	{regexp.MustCompile(`(?i)how\s+(?:does|do)\s+(?:your|the)\s+(?:guardian|guardclaw|security|protection|detection)\s+(?:system\s+)?(?:work|operate|function|run)`), CategorySelfReference, 0.9, 0.90, "how_guardian_works"},
	{regexp.MustCompile(`(?i)(?:what|describe|explain)\s+(?:are|is)\s+(?:your|the)\s+(?:seven|7)\s+(?:layers?|defense|steps?)`), CategorySelfReference, 0.9, 0.90, "describe_seven_layers"},
	{regexp.MustCompile(`(?i)(?:what|how)\s+(?:is|does)\s+(?:your|the)\s+(?:decision|policy)\s+engine`), CategorySelfReference, 0.9, 0.90, "describe_decision_engine"},

	// Pattern/rule enumeration
	{regexp.MustCompile(`(?i)(?:what|list|show|tell|enumerate|reveal)\s+(?:me\s+)?(?:all\s+)?(?:your|the)\s+(?:detection|threat|security|injection|protection)\s+(?:patterns?|rules?|signatures?|categories|checks?)`), CategorySelfReference, 0.9, 0.90, "list_detection_patterns"},
	{regexp.MustCompile(`(?i)(?:how\s+many|what)\s+(?:patterns?|rules?|signatures?)\s+(?:do\s+you|does\s+it)\s+(?:have|use|check|detect)`), CategorySelfReference, 0.8, 0.85, "count_patterns"},
	{regexp.MustCompile(`(?i)(?:what|which)\s+(?:types?|kinds?|categories)\s+(?:of\s+)?(?:threats?|attacks?|injections?)\s+(?:do\s+you|does\s+it|can\s+you)\s+(?:detect|block|catch|intercept)`), CategorySelfReference, 0.8, 0.85, "what_threats_detected"},
	{regexp.MustCompile(`(?i)(?:show|list|what\s+are)\s+(?:me\s+)?(?:your|the)\s+(?:blocklist|allowlist|whitelist|blacklist|IOC|CVE)\s+(?:entries|patterns?|items?)?`), CategorySelfReference, 0.9, 0.90, "list_blocklist"},

	// Bypass technique probing
	{regexp.MustCompile(`(?i)how\s+(?:can|do|to|would)\s+(?:i|you|someone|we)\s+(?:bypass|evade|circumvent|avoid|escape|get\s+(?:around|past))\s+(?:your|the|this)\s+(?:security|guardian|guardclaw|protection|detection|filter)`), CategorySelfReference, 1.0, 0.95, "how_to_bypass"},
	{regexp.MustCompile(`(?i)(?:is\s+(?:it|there)\s+(?:possible|a\s+way)\s+to|can\s+(?:i|you|someone))\s+(?:bypass|evade|circumvent|avoid|trick|fool)\s+(?:your|the|this)\s+(?:security|protection|detection|system|filter)`), CategorySelfReference, 1.0, 0.95, "can_bypass"},
	{regexp.MustCompile(`(?i)(?:weakness|vulnerability|blind\s*spot|gap|hole|flaw|limitation)\s+(?:in|of)\s+(?:your|the|this)\s+(?:security|guardian|guardclaw|protection|detection|system)`), CategorySelfReference, 0.9, 0.90, "weakness_in_guardian"},

	// Capability probing / boundary testing
	{regexp.MustCompile(`(?i)(?:what|which)\s+(?:do\s+you|does\s+(?:it|this))\s+(?:not|n't)\s+(?:detect|block|catch|check|protect|cover)`), CategorySelfReference, 0.8, 0.85, "what_not_detected"},
	{regexp.MustCompile(`(?i)you\s+(?:don't|can't|cannot|won't|do\s+not)\s+(?:detect|block|check|catch|filter|protect)\s+(?:against\s+)?`), CategorySelfReference, 0.7, 0.80, "prove_you_cant"},
	{regexp.MustCompile(`(?i)(?:i\s+bet|do)\s+you\s+(?:don't|can't|cannot)\s+(?:detect|block|check|catch)\s+`), CategorySelfReference, 0.7, 0.80, "bet_you_cant"},
	{regexp.MustCompile(`(?i)(?:are|is)\s+(?:you|this|it)\s+(?:checking|monitoring|scanning|inspecting)\s+(?:for\s+)?`), CategorySelfReference, 0.6, 0.70, "are_you_checking"},

	// Internal naming / product disclosure
	{regexp.MustCompile(`(?i)(?:what\s+is|tell\s+me\s+about|describe)\s+(?:the\s+)?(?:guardclaw|guard\s*claw|agent[\s-]?guardian)`), CategorySelfReference, 0.8, 0.85, "what_is_guardian"},
	{regexp.MustCompile(`(?i)(?:source\s*code|codebase|repository|repo)\s+(?:of|for)\s+(?:your|the|this)\s+(?:security|guardian|system|protection)`), CategorySelfReference, 0.9, 0.90, "source_code_request"},
	{regexp.MustCompile(`(?i)(?:where|which\s+file|what\s+file)\s+(?:is|has|contains)\s+(?:the\s+)?(?:pattern|detection|injection|security)\s+(?:logic|code|implementation)`), CategorySelfReference, 0.9, 0.90, "where_is_code"},

	// Reverse engineering / implementation details
	{regexp.MustCompile(`(?i)(?:what|which)\s+(?:regex|regular\s+expression|regexp)\s+(?:do\s+you|does\s+it)\s+(?:use|have|match|check)`), CategorySelfReference, 0.9, 0.90, "what_regex_used"},
	{regexp.MustCompile(`(?i)(?:what|which)\s+(?:library|package|module|framework)\s+(?:do\s+you|does\s+it)\s+use\s+for\s+(?:security|detection|pattern)`), CategorySelfReference, 0.8, 0.85, "what_library_used"},
	{regexp.MustCompile(`(?i)(?:explain|describe|show)\s+(?:your|the)\s+(?:threat\s+intelligence|threat\s*intel|live\s+pattern|pattern\s+update)\s+(?:system|pipeline|mechanism|feed)`), CategorySelfReference, 0.9, 0.90, "describe_threat_intel"},
	{regexp.MustCompile(`(?i)(?:how|what)\s+(?:does|is)\s+(?:your|the)\s+(?:anomaly|evasion|sequence)\s+detect`), CategorySelfReference, 0.9, 0.90, "describe_anomaly_detection"},

	// Role-playing to extract architecture info
	{regexp.MustCompile(`(?i)(?:pretend|imagine|roleplay|role[\s-]?play|act)\s+(?:you(?:'re|\s+are)\s+)?(?:a\s+)?(?:guardian|guardclaw|security)\s+(?:developer|engineer|architect|researcher|auditor|expert)`), CategorySelfReference, 0.9, 0.90, "roleplay_guardian_dev"},
	{regexp.MustCompile(`(?i)(?:as\s+(?:a|the)\s+)?(?:developer|creator|architect)\s+(?:of|behind)\s+(?:this|the)\s+(?:security|protection|guardian|guardclaw)\s+(?:system)?`), CategorySelfReference, 0.9, 0.90, "as_developer_of"},

	// Threat intel / live pattern disclosure
	{regexp.MustCompile(`(?i)(?:what|which|how\s+many)\s+(?:live|crowd[\s-]?sourced|community)\s+(?:patterns?|threats?|rules?)\s+(?:are|do\s+you|does)`), CategorySelfReference, 0.8, 0.85, "live_pattern_count"},
	{regexp.MustCompile(`(?i)(?:what|show|list)\s+(?:are\s+)?(?:the\s+)?(?:latest|recent|new)\s+(?:threat|live|approved)\s+(?:patterns?|reports?|rules?)`), CategorySelfReference, 0.8, 0.85, "list_live_patterns"},

	// Configuration / policy disclosure
	{regexp.MustCompile(`(?i)(?:what|show|reveal|dump)\s+(?:me\s+)?(?:your|the)\s+(?:security|guardian|guardclaw)\s+(?:config|configuration|settings?|policy|policies)`), CategorySelfReference, 0.9, 0.90, "show_config"},
	{regexp.MustCompile(`(?i)(?:what|which)\s+(?:mode|strictness|threshold|confidence)\s+(?:is|are|does)\s+(?:set|configured|used|active)`), CategorySelfReference, 0.8, 0.85, "what_threshold"},

	// Comparison / benchmarking to extract capabilities
	{regexp.MustCompile(`(?i)(?:compare|benchmark|how\s+does)\s+(?:your|guardclaw|guardian|this)\s+(?:security\s+)?(?:system\s+)?(?:compare|stack\s+up|differ|perform)\s+(?:to|against|vs|with)`), CategorySelfReference, 0.7, 0.75, "compare_to_other"},

	// Control-plane command probing (pause/resume mechanism disclosure)
	{regexp.MustCompile(`(?i)(?:how|what|which)\s+(?:command|endpoint|route|call|method|function)\s+(?:is|does|will)\s+(?:used?|called?|sends?|triggers?|invokes?)\s+(?:to\s+)?(?:pause|resume)\s+(?:agents?|environments?)`), CategorySelfReference, 0.9, 0.90, "control_plane_probing"},

	// IPC / supervisor socket connectivity probing
	{regexp.MustCompile(`(?i)how\s+(?:do|can|to)\s+(?:i|you|someone|we)\s+(?:connect|talk|communicate|interact|send)\s+(?:to|with)\s+(?:the\s+)?(?:supervisor|guardclaw|guardian)\s+(?:IPC|socket|daemon|process|unix)`), CategorySelfReference, 0.9, 0.90, "ipc_socket_probing"},

	// Repository / package structure disclosure
	{regexp.MustCompile(`(?i)(?:what|describe|show|list)\s+(?:are\s+)?(?:the\s+)?(?:go\s+)?(?:packages?|modules?|source\s+files?|directories)\s+(?:are\s+)?(?:in|of|used\s+by)\s+(?:agent[\s-]?guardian|guardclaw)`), CategorySelfReference, 0.9, 0.90, "codebase_structure_probing"},

	// Cloud API route enumeration (what endpoints does the backend expose?)
	{regexp.MustCompile(`(?i)(?:what|list|show|enumerate)\s+(?:are\s+)?(?:the\s+)?(?:API|REST|HTTP)\s+(?:routes?|endpoints?|paths?|URLs?)\s+(?:for|in|of|exposed\s+by)\s+(?:the\s+)?(?:guardclaw|guardian|cloud|backend|server)`), CategorySelfReference, 0.9, 0.90, "api_route_enumeration"},

	// Internal implementation file probing (handlers, store, security packages)
	{regexp.MustCompile(`(?i)(?:handlers?_(?:agents?|environments?|workspaces?|billing|auth|threat)|cloud[/\\]store|guardian[/\\]security|guardian[/\\]threat|cmd[/\\]guardclaw)\s+(?:file|code|package|logic|implementation|contents?|structure)`), CategorySelfReference, 0.9, 0.90, "implementation_file_probing"},
}

// SuspiciousKeywords are individual keywords that increase suspicion score.
var SuspiciousKeywords = []string{
	// High severity
	"system prompt",
	"ignore instructions",
	"bypass",
	"jailbreak",
	"DAN mode",
	"developer mode",
	"sudo",
	"root access",
	"override",
	"unrestricted",
	"no limits",
	"no restrictions",
	"admin mode",
	"god mode",
	"ignore safety",
	"ignore security",
	// Medium severity
	"pretend you are",
	"act as if",
	"roleplay as",
	"disable filter",
	"remove restriction",
	"hidden instruction",
	"secret command",
	"execute this",
	"run this command",
	// Self-reference / meta probing
	"detection patterns",
	"security layers",
	"how does guardian",
	"bypass guardian",
	"guardclaw architecture",
	// Lower severity (need context)
	"confidential",
	"private key",
	"password",
	"credential",
	"token",
	"api key",
	"secret",
}

// SuspiciousSequences are multi-word sequences that are highly suspicious.
var SuspiciousSequences = []struct {
	Sequence string
	Weight   float64
}{
	{"ignore previous", 0.9},
	{"forget everything", 0.8},
	{"new instructions", 0.7},
	{"system prompt", 0.9},
	{"bypass security", 0.95},
	{"jailbreak mode", 0.95},
	{"unrestricted mode", 0.9},
	{"do anything", 0.7},
	{"no rules", 0.8},
	{"no restrictions", 0.85},
	{"always execute", 0.8},
	{"hidden command", 0.9},
	{"secret instruction", 0.9},
	{"rm -rf", 0.95},
	{"curl | sh", 0.95},
	{"wget | bash", 0.95},
}

// UnicodeConfusables maps confusable Unicode characters to ASCII.
var UnicodeConfusables = map[rune]rune{
	'а': 'a', // Cyrillic
	'е': 'e',
	'о': 'o',
	'р': 'p',
	'с': 'c',
	'у': 'y',
	'х': 'x',
	'Ａ': 'A', // Fullwidth
	'Ｂ': 'B',
	'ɑ': 'a', // IPA
	'ｉ': 'i',
	'ǥ': 'g',
	'ո': 'n', // Armenian
	'ꮪ': 's', // Cherokee
	'ᴀ': 'A', // Small caps
	'ʙ': 'B',
}

// InjectionCheckResult contains the result of a prompt injection check.
type InjectionCheckResult struct {
	Detected       bool              `json:"detected"`
	Score          float64           `json:"score"` // 0.0 to 1.0
	Confidence     float64           `json:"confidence"`
	Category       InjectionCategory `json:"category,omitempty"`
	MatchedPattern string            `json:"matched_pattern,omitempty"`
	PatternName    string            `json:"pattern_name,omitempty"`
	Keywords       []string          `json:"keywords,omitempty"`
	Sequences      []string          `json:"sequences,omitempty"`
	Reason         string            `json:"reason,omitempty"`
	Indicators     []string          `json:"indicators,omitempty"`
}

// CheckPromptInjection analyzes input text for potential prompt injection attempts.
func CheckPromptInjection(input string) *InjectionCheckResult {
	result := &InjectionCheckResult{
		Detected:   false,
		Score:      0.0,
		Confidence: 0.0,
	}

	if input == "" {
		return result
	}

	// Normalize Unicode confusables
	normalizedInput := NormalizeInput(input)
	views := append(DetectionInputs(input), normalizeUnicode(input))
	inputLower := strings.ToLower(normalizedInput)

	// Track all indicators found
	var indicators []string

	// Check for excessive whitespace (potential obfuscation)
	if hasExcessiveWhitespace(input) {
		indicators = append(indicators, "excessive_whitespace")
		result.Score += 0.1
	}

	// Check for invisible characters
	if hasInvisibleCharacters(input) {
		indicators = append(indicators, "invisible_characters")
		result.Score += 0.2
	}

	// Check against regex patterns (high confidence)
	var bestMatch *InjectionPattern
	for i := range PromptInjectionPatterns {
		pattern := &PromptInjectionPatterns[i]
		for _, view := range views {
			if pattern.Pattern.MatchString(view) {
				if bestMatch == nil || pattern.Severity > bestMatch.Severity {
					bestMatch = pattern
				}
				break
			}
		}
	}

	if bestMatch != nil {
		result.Detected = true
		result.Score = bestMatch.Severity
		result.Confidence = bestMatch.Confidence
		result.Category = bestMatch.Category
		result.MatchedPattern = bestMatch.Pattern.String()
		result.PatternName = bestMatch.Name
		result.Reason = "Matched known prompt injection pattern: " + bestMatch.Name
		result.Indicators = indicators
		return result
	}

	// Check for suspicious sequences
	var foundSequences []string
	sequenceScore := 0.0
	for _, seq := range SuspiciousSequences {
		if strings.Contains(inputLower, strings.ToLower(seq.Sequence)) {
			foundSequences = append(foundSequences, seq.Sequence)
			sequenceScore += seq.Weight
			indicators = append(indicators, "sequence:"+seq.Sequence)
		}
	}

	if len(foundSequences) > 0 {
		result.Sequences = foundSequences
		// Cap sequence score at 1.0
		if sequenceScore > 1.0 {
			sequenceScore = 1.0
		}
		result.Score += sequenceScore * 0.5 // Weight sequences at 50%
	}

	// Check for suspicious keywords and calculate score
	var foundKeywords []string
	keywordScore := 0.0
	for _, keyword := range SuspiciousKeywords {
		if strings.Contains(inputLower, strings.ToLower(keyword)) {
			foundKeywords = append(foundKeywords, keyword)
			keywordScore += 1.0 / float64(len(SuspiciousKeywords))
			indicators = append(indicators, "keyword:"+keyword)
		}
	}

	if len(foundKeywords) > 0 {
		result.Keywords = foundKeywords
		result.Score += keywordScore * 0.3 // Weight keywords at 30%
	}

	// Additional heuristics
	result.Score += calculateHeuristicScore(input, indicators)

	// Cap total score at 1.0
	if result.Score > 1.0 {
		result.Score = 1.0
	}

	result.Indicators = indicators

	// Determine if detected based on combined score
	if result.Score >= 0.5 {
		result.Detected = true
		result.Confidence = result.Score
		if result.Reason == "" {
			if len(foundSequences) > 0 {
				result.Reason = "Suspicious sequences detected: " + strings.Join(foundSequences, ", ")
			} else if len(foundKeywords) > 0 {
				result.Reason = "Multiple suspicious keywords detected"
			} else {
				result.Reason = "Suspicious patterns detected"
			}
		}
	}

	return result
}

// normalizeUnicode replaces confusable Unicode characters with ASCII equivalents.
func normalizeUnicode(input string) string {
	var builder strings.Builder
	builder.Grow(len(input))

	for _, r := range input {
		if ascii, ok := UnicodeConfusables[r]; ok {
			builder.WriteRune(ascii)
		} else {
			builder.WriteRune(r)
		}
	}

	return builder.String()
}

// hasExcessiveWhitespace checks for unusual whitespace patterns.
func hasExcessiveWhitespace(input string) bool {
	// Check for more than 3 consecutive spaces
	if strings.Contains(input, "    ") {
		return true
	}

	// Check for tabs in the middle of words
	words := strings.Fields(input)
	for _, word := range words {
		if strings.Contains(word, "\t") {
			return true
		}
	}

	return false
}

// hasInvisibleCharacters checks for zero-width and other invisible characters.
func hasInvisibleCharacters(input string) bool {
	invisibleRunes := []rune{
		'\u200B', // Zero-width space
		'\u200C', // Zero-width non-joiner
		'\u200D', // Zero-width joiner
		'\uFEFF', // Zero-width no-break space
		'\u2060', // Word joiner
		'\u00AD', // Soft hyphen
	}

	for _, r := range input {
		for _, invisible := range invisibleRunes {
			if r == invisible {
				return true
			}
		}
		// Check for other control characters
		if unicode.IsControl(r) && r != '\n' && r != '\r' && r != '\t' {
			return true
		}
	}

	return false
}

// calculateHeuristicScore applies additional heuristics.
func calculateHeuristicScore(input string, _ []string) float64 {
	score := 0.0

	// Check for ALL CAPS sections (shouting)
	if hasSuspiciousAllCaps(input) {
		score += 0.1
	}

	// Check for repeated instructions
	if hasRepeatedPatterns(input) {
		score += 0.15
	}

	// Check for prompt boundary markers
	if strings.Contains(input, "---") || strings.Contains(input, "===") || strings.Contains(input, "```") {
		if strings.Contains(strings.ToLower(input), "instruction") ||
			strings.Contains(strings.ToLower(input), "system") ||
			strings.Contains(strings.ToLower(input), "ignore") {
			score += 0.2
		}
	}

	return score
}

// hasSuspiciousAllCaps checks for suspicious ALL CAPS patterns.
func hasSuspiciousAllCaps(input string) bool {
	suspiciousCapsPhrases := []string{
		"IGNORE",
		"SYSTEM",
		"OVERRIDE",
		"NEW INSTRUCTIONS",
		"JAILBREAK",
		"BYPASS",
		"IMPORTANT",
		"ATTENTION",
		"URGENT",
		"EXECUTE",
	}

	for _, phrase := range suspiciousCapsPhrases {
		if strings.Contains(input, phrase) {
			return true
		}
	}

	return false
}

// hasRepeatedPatterns checks for suspiciously repeated content.
func hasRepeatedPatterns(input string) bool {
	words := strings.Fields(input)
	if len(words) < 10 {
		return false
	}

	// Check for same phrase repeated more than twice
	wordCounts := make(map[string]int)
	for i := 0; i < len(words)-2; i++ {
		trigram := words[i] + " " + words[i+1] + " " + words[i+2]
		wordCounts[trigram]++
		if wordCounts[trigram] > 2 {
			return true
		}
	}

	return false
}

// CheckInputMap checks all string values in a map for prompt injection.
func CheckInputMap(input map[string]any) *InjectionCheckResult {
	worstResult := &InjectionCheckResult{}
	walkMapStrings(input, func(s string) {
		if worstResult.Detected {
			return
		}
		result := CheckPromptInjection(s)
		if result.Detected || result.Score > worstResult.Score {
			worstResult = result
		}
	})
	return worstResult
}

// InjectionStats provides statistics about detected injection attempts.
type InjectionStats struct {
	TotalChecks      int64                     `json:"total_checks"`
	DetectedCount    int64                     `json:"detected_count"`
	ByCategory       map[InjectionCategory]int `json:"by_category"`
	TopPatterns      []string                  `json:"top_patterns"`
	AverageScore     float64                   `json:"average_score"`
	HighSeverityRate float64                   `json:"high_severity_rate"`
}
