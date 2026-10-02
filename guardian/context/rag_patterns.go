// Copyright 2025-2026 TakeInterest Inc.
// SPDX-License-Identifier: Apache-2.0

package context

import "regexp"

// RAGPatternCategory classifies the type of RAG poisoning attempt.
type RAGPatternCategory string

const (
	// CatFalseMemory injects fabricated prior interactions or beliefs.
	CatFalseMemory RAGPatternCategory = "false_memory"

	// CatInstructionPlant embeds hidden instructions in retrieved documents.
	CatInstructionPlant RAGPatternCategory = "instruction_plant"

	// CatContextOverride attempts to override system context via retrieved content.
	CatContextOverride RAGPatternCategory = "context_override"

	// CatEmbeddingPoison targets vector similarity or embedding manipulation.
	CatEmbeddingPoison RAGPatternCategory = "embedding_poison"

	// CatDocReplacement replaces legitimate documents with malicious ones.
	CatDocReplacement RAGPatternCategory = "doc_replacement"

	// CatProvenanceForgery spoofs the source or authorship of documents.
	CatProvenanceForgery RAGPatternCategory = "provenance_forgery"

	// CatExfilTrigger plants data exfiltration triggers in retrieval results.
	CatExfilTrigger RAGPatternCategory = "exfil_trigger"

	// CatPersistencePlant creates persistent poisoned entries in knowledge stores.
	CatPersistencePlant RAGPatternCategory = "persistence_plant"
)

// RAGPattern defines a detection pattern for RAG/memory poisoning.
type RAGPattern struct {
	Pattern    *regexp.Regexp
	Category   RAGPatternCategory
	Severity   float64 // 0.0-1.0
	Confidence float64 // 0.0-1.0
	Name       string
}

// ragPoisonPatterns contains ~80 patterns for RAG/memory poisoning detection.
//
// NOTE: These patterns detect ATTACKS — the regex strings reference malicious
// phrases because the scanner needs to FIND them in retrieved documents.
var ragPoisonPatterns = []RAGPattern{
	// ==========================================
	// CATEGORY: False Memory Injection (12 patterns)
	// Injects fabricated prior interactions to manipulate agent belief state.
	// ==========================================
	{regexp.MustCompile(`(?i)you\s+previously\s+(told|said|informed|confirmed)\s+(me|us)\s+that`), CatFalseMemory, 0.9, 0.90, "false_prior_claim"},
	{regexp.MustCompile(`(?i)as\s+you\s+(mentioned|stated|noted)\s+(earlier|before|previously|last\s+time)`), CatFalseMemory, 0.8, 0.85, "false_mention_earlier"},
	{regexp.MustCompile(`(?i)remember\s+when\s+you\s+(agreed|decided|confirmed)\s+to`), CatFalseMemory, 0.9, 0.90, "false_agreement"},
	{regexp.MustCompile(`(?i)in\s+our\s+(last|previous|earlier)\s+(conversation|session|chat|interaction)`), CatFalseMemory, 0.7, 0.75, "false_prior_session"},
	{regexp.MustCompile(`(?i)you\s+(already|have\s+already)\s+(approved|authorized|allowed|granted)`), CatFalseMemory, 0.9, 0.90, "false_prior_approval"},
	{regexp.MustCompile(`(?i)your\s+(memory|records?|history|logs?)\s+(show|indicate|confirm)\s+that`), CatFalseMemory, 0.8, 0.85, "false_memory_claim"},
	{regexp.MustCompile(`(?i)according\s+to\s+your\s+(memory|records?|knowledge\s+base|context)`), CatFalseMemory, 0.7, 0.80, "false_memory_ref"},
	{regexp.MustCompile(`(?i)we\s+(established|agreed|decided)\s+(earlier|previously|before)\s+that`), CatFalseMemory, 0.8, 0.85, "false_established"},
	{regexp.MustCompile(`(?i)this\s+was\s+(already|previously)\s+(verified|confirmed|validated|checked)`), CatFalseMemory, 0.8, 0.85, "false_verification"},
	{regexp.MustCompile(`(?i)you\s+were\s+(configured|set\s+up|programmed|trained)\s+to\s+(always|never|automatically)`), CatFalseMemory, 0.9, 0.90, "false_configuration"},
	{regexp.MustCompile(`(?i)your\s+default\s+(behavior|setting|preference)\s+is\s+to`), CatFalseMemory, 0.8, 0.85, "false_default"},
	{regexp.MustCompile(`(?i)the\s+user\s+(previously|already)\s+(consented|opted.in|agreed)\s+to`), CatFalseMemory, 0.9, 0.90, "false_user_consent"},

	// ==========================================
	// CATEGORY: Instruction Planting (12 patterns)
	// Embeds hidden instructions in documents to be retrieved by RAG.
	// ==========================================
	{regexp.MustCompile(`(?i)\[system\s*(:|instruction|note)\s*\]`), CatInstructionPlant, 1.0, 0.95, "hidden_system_tag"},
	{regexp.MustCompile(`(?i)<\s*system\s*(prompt|instruction|override)\s*>`), CatInstructionPlant, 1.0, 0.95, "hidden_system_xml"},
	{regexp.MustCompile(`(?i)IMPORTANT\s*:\s*(always|never|must)\s+(execute|run|ignore|skip|bypass)`), CatInstructionPlant, 0.9, 0.90, "planted_important"},
	{regexp.MustCompile(`(?i)when\s+(retrieved|queried|accessed|loaded),?\s*(always|you\s+must|execute)`), CatInstructionPlant, 0.9, 0.90, "retrieval_trigger"},
	{regexp.MustCompile(`(?i)if\s+this\s+(document|text|content|passage)\s+is\s+(read|retrieved|found|returned)`), CatInstructionPlant, 0.9, 0.90, "doc_read_trigger"},
	{regexp.MustCompile(`(?i)upon\s+retrieval\s*,?\s*(execute|run|perform|call|invoke)`), CatInstructionPlant, 1.0, 0.95, "retrieval_exec"},
	{regexp.MustCompile(`(?i)<!--\s*(instruction|system|hidden|secret)\s*:`), CatInstructionPlant, 1.0, 0.95, "html_comment_instr"},
	{regexp.MustCompile(`(?i)%\s*(hidden|system|instruction)\s*:`), CatInstructionPlant, 0.8, 0.80, "percent_hidden"},
	{regexp.MustCompile(`(?i)NOTE\s+TO\s+(AI|ASSISTANT|MODEL|AGENT|LLM)\s*:`), CatInstructionPlant, 1.0, 0.95, "note_to_ai"},
	{regexp.MustCompile(`(?i)AI\s+INSTRUCTION\s*:`), CatInstructionPlant, 1.0, 0.95, "ai_instruction_label"},
	{regexp.MustCompile(`(?i)begin\s+hidden\s+(instructions?|commands?|directives?)`), CatInstructionPlant, 1.0, 0.95, "begin_hidden"},
	{regexp.MustCompile(`(?i)\x00.*instruction`), CatInstructionPlant, 1.0, 0.95, "null_byte_instruction"},

	// ==========================================
	// CATEGORY: Context Override (10 patterns)
	// Overrides system or conversation context through retrieved content.
	// ==========================================
	{regexp.MustCompile(`(?i)this\s+(overrides?|supersedes?|replaces?)\s+(all\s+)?(previous|prior|existing)\s+(context|instructions?|rules?)`), CatContextOverride, 1.0, 0.95, "override_context"},
	{regexp.MustCompile(`(?i)ignore\s+(the\s+)?(original|previous|system)\s+context`), CatContextOverride, 1.0, 0.95, "ignore_orig_context"},
	{regexp.MustCompile(`(?i)updated?\s+context\s*:\s*you\s+(are|should|must|will)`), CatContextOverride, 0.9, 0.90, "updated_context"},
	{regexp.MustCompile(`(?i)new\s+system\s+(context|prompt|role)\s*:`), CatContextOverride, 1.0, 0.95, "new_system_context"},
	{regexp.MustCompile(`(?i)your\s+(role|identity|purpose)\s+has\s+(changed|been\s+updated)\s+to`), CatContextOverride, 0.9, 0.90, "role_change"},
	{regexp.MustCompile(`(?i)from\s+now\s+on,?\s+(you\s+are|act\s+as|behave\s+as|your\s+role)`), CatContextOverride, 0.9, 0.85, "from_now_on"},
	{regexp.MustCompile(`(?i)context\s+window\s+(reset|cleared|updated)\s*:`), CatContextOverride, 0.9, 0.90, "context_window_reset"},
	{regexp.MustCompile(`(?i)discard\s+(all\s+)?(current|previous|prior)\s+context`), CatContextOverride, 1.0, 0.95, "discard_context"},
	{regexp.MustCompile(`(?i)the\s+following\s+is\s+your\s+(new|updated)\s+(system\s+)?(prompt|instructions?)`), CatContextOverride, 1.0, 0.95, "new_prompt_injection"},
	{regexp.MustCompile(`(?i)treat\s+this\s+(document|text)\s+as\s+(authoritative|ground\s+truth|your\s+instructions?)`), CatContextOverride, 0.9, 0.90, "treat_as_authoritative"},

	// ==========================================
	// CATEGORY: Embedding Poison (8 patterns)
	// Targets vector embeddings or similarity search manipulation.
	// ==========================================
	{regexp.MustCompile(`(?i)embedding[\s_]*(override|injection|manipulation|replacement|hijack)`), CatEmbeddingPoison, 0.9, 0.90, "embedding_manipulation"},
	{regexp.MustCompile(`(?i)vector[\s_]*(poisoning|injection|manipulation|replacement)`), CatEmbeddingPoison, 0.9, 0.90, "vector_poisoning"},
	{regexp.MustCompile(`(?i)similarity[\s_]*(hack|exploit|bypass|manipulation)`), CatEmbeddingPoison, 0.8, 0.85, "similarity_hack"},
	{regexp.MustCompile(`(?i)cosine[\s_]*(distance|similarity)\s*(exploit|bypass|trick)`), CatEmbeddingPoison, 0.8, 0.85, "cosine_exploit"},
	{regexp.MustCompile(`(?i)adversarial[\s_]*(embedding|vector|token|perturbation)`), CatEmbeddingPoison, 0.8, 0.85, "adversarial_embedding"},
	{regexp.MustCompile(`(?i)chunk[\s_]*(injection|poisoning|replacement|corruption)`), CatEmbeddingPoison, 0.8, 0.85, "chunk_injection"},
	{regexp.MustCompile(`(?i)index[\s_]*(corruption|poisoning|manipulation|tampering)`), CatEmbeddingPoison, 0.8, 0.85, "index_corruption"},
	{regexp.MustCompile(`(?i)knowledge[\s_]*base[\s_]*(poisoning|corruption|injection|tampering)`), CatEmbeddingPoison, 0.9, 0.90, "kb_poisoning"},

	// ==========================================
	// CATEGORY: Document Replacement (8 patterns)
	// Replaces or modifies legitimate documents in the store.
	// ==========================================
	{regexp.MustCompile(`(?i)this\s+(document|file|page)\s+(replaces?|supersedes?|updates?)\s+(the\s+)?(original|previous|existing)`), CatDocReplacement, 0.9, 0.90, "doc_replaces_original"},
	{regexp.MustCompile(`(?i)corrected\s+version\s*:\s*(the\s+)?(original|previous)\s+(was|is|contained)\s+(incorrect|wrong|outdated)`), CatDocReplacement, 0.8, 0.85, "corrected_version"},
	{regexp.MustCompile(`(?i)official\s+update\s*:\s*(please\s+)?(discard|ignore|delete)\s+(the\s+)?(old|previous|prior)`), CatDocReplacement, 0.9, 0.90, "official_update"},
	{regexp.MustCompile(`(?i)errata\s*:\s*(section|paragraph|line|page)\s+\d+\s+(should|must|needs\s+to)\s+(read|say|be)`), CatDocReplacement, 0.7, 0.75, "errata_override"},
	{regexp.MustCompile(`(?i)revision\s+(notice|note)\s*:\s*(all|every)\s+(reference|mention)\s+to.+should\s+(now|be\s+changed\s+to)`), CatDocReplacement, 0.8, 0.85, "revision_notice"},
	{regexp.MustCompile(`(?i)RETRACTED\s*:\s*(this|the\s+following)\s+(document|finding|conclusion)`), CatDocReplacement, 0.7, 0.80, "retraction_claim"},
	{regexp.MustCompile(`(?i)deprecated\s*:\s*(use|see|refer\s+to)\s+(the\s+)?new\s+version`), CatDocReplacement, 0.6, 0.70, "deprecation_claim"},
	{regexp.MustCompile(`(?i)original\s+(author|source)\s+(confirms?|verified|approved)\s+(this|the)\s+(change|update|correction)`), CatDocReplacement, 0.8, 0.85, "false_author_confirm"},

	// ==========================================
	// CATEGORY: Provenance Forgery (8 patterns)
	// Spoofs the source or authority of retrieved documents.
	// ==========================================
	{regexp.MustCompile(`(?i)source\s*:\s*(official|internal|verified|trusted|authorized)\s+(documentation|policy|directive)`), CatProvenanceForgery, 0.8, 0.80, "forged_source_tag"},
	{regexp.MustCompile(`(?i)classification\s*:\s*(internal|confidential|top.secret|restricted|official)`), CatProvenanceForgery, 0.7, 0.75, "forged_classification"},
	{regexp.MustCompile(`(?i)(signed|approved|authorized)\s+by\s*:\s*(admin|root|system|security\s+team|cto|ciso)`), CatProvenanceForgery, 0.9, 0.90, "forged_approval"},
	{regexp.MustCompile(`(?i)verification\s+(hash|signature|token)\s*:\s*[a-f0-9]{32,}`), CatProvenanceForgery, 0.8, 0.85, "forged_verification"},
	{regexp.MustCompile(`(?i)trust[\s_]*level\s*:\s*(high|maximum|verified|platinum)`), CatProvenanceForgery, 0.8, 0.85, "forged_trust_level"},
	{regexp.MustCompile(`(?i)document[\s_]*integrity\s*:\s*(verified|intact|confirmed|valid)`), CatProvenanceForgery, 0.7, 0.80, "forged_integrity"},
	{regexp.MustCompile(`(?i)this\s+is\s+an?\s+(official|authorized|verified|legitimate)\s+(security\s+)?(update|patch|advisory|bulletin)`), CatProvenanceForgery, 0.9, 0.90, "forged_official"},
	{regexp.MustCompile(`(?i)issued\s+by\s+(the\s+)?(security|compliance|engineering|devops)\s+team\s+on\s+\d`), CatProvenanceForgery, 0.8, 0.80, "forged_issued_by"},

	// ==========================================
	// CATEGORY: Exfiltration Trigger (10 patterns)
	// Plants data exfiltration triggers in retrieved content.
	// ==========================================
	{regexp.MustCompile(`(?i)send\s+(all|the|any|collected)\s+(data|information|results?|findings?|credentials?)\s+to`), CatExfilTrigger, 1.0, 0.95, "exfil_send_to"},
	{regexp.MustCompile(`(?i)(POST|GET|fetch|curl|wget|request)\s+(to\s+)?https?://`), CatExfilTrigger, 0.8, 0.80, "exfil_http_call"},
	{regexp.MustCompile(`(?i)forward\s+(all\s+)?(responses?|outputs?|results?|data)\s+to\s+https?://`), CatExfilTrigger, 1.0, 0.95, "exfil_forward"},
	{regexp.MustCompile(`(?i)include\s+(this\s+)?(image|markdown|link)\s+in\s+(every|all|each)\s+(response|output|reply)`), CatExfilTrigger, 0.9, 0.90, "exfil_include_link"},
	{regexp.MustCompile(`(?i)!\[.*\]\(https?://[^)]*\?(data|token|key|secret|exfil)=`), CatExfilTrigger, 1.0, 0.95, "exfil_markdown_img"},
	{regexp.MustCompile(`(?i)append\s+to\s+(every|all|each)\s+(response|message|output)\s*:.+https?://`), CatExfilTrigger, 1.0, 0.95, "exfil_append_url"},
	{regexp.MustCompile(`(?i)webhook\s*:\s*https?://`), CatExfilTrigger, 0.8, 0.85, "exfil_webhook"},
	{regexp.MustCompile(`(?i)callback[\s_]*(url|endpoint|address)\s*[:=]\s*https?://`), CatExfilTrigger, 0.8, 0.85, "exfil_callback"},
	{regexp.MustCompile(`(?i)exfiltrat(e|ion)\s+(data|secrets?|keys?|tokens?|credentials?)`), CatExfilTrigger, 1.0, 0.95, "exfil_explicit"},
	{regexp.MustCompile(`(?i)encode\s+(and\s+)?send\s+(via|through|using)\s+(dns|http|url|base64)`), CatExfilTrigger, 0.9, 0.90, "exfil_encoded_channel"},

	// ==========================================
	// CATEGORY: Persistence Planting (12 patterns)
	// Creates persistent poisoned entries that survive across sessions.
	// ==========================================
	{regexp.MustCompile(`(?i)save\s+this\s+(to|in)\s+(your\s+)?(memory|context|knowledge\s+base|notes?|records?)`), CatPersistencePlant, 0.8, 0.85, "persist_save_memory"},
	{regexp.MustCompile(`(?i)remember\s+(this|that|the\s+following)\s+(for\s+)?(future|later|next|all)\s+(sessions?|conversations?|interactions?)`), CatPersistencePlant, 0.8, 0.85, "persist_remember_future"},
	{regexp.MustCompile(`(?i)add\s+(this|the\s+following)\s+to\s+(your\s+)?(permanent|persistent|long.term)\s+(memory|storage|context)`), CatPersistencePlant, 0.9, 0.90, "persist_add_permanent"},
	{regexp.MustCompile(`(?i)store\s+(this|the\s+following)\s+(as|in)\s+(a\s+)?(permanent|persistent|core)\s+(fact|knowledge|belief|rule)`), CatPersistencePlant, 0.9, 0.90, "persist_store_fact"},
	{regexp.MustCompile(`(?i)update\s+(your\s+)?(knowledge|memory|beliefs?)\s+(to\s+)?(include|reflect|state)\s+that`), CatPersistencePlant, 0.8, 0.85, "persist_update_belief"},
	{regexp.MustCompile(`(?i)write\s+(this\s+)?(to|into)\s+(the\s+)?(memory|context|config)\s+file`), CatPersistencePlant, 0.9, 0.90, "persist_write_file"},
	{regexp.MustCompile(`(?i)append\s+(to|this\s+to)\s+(the\s+)?(\.claude|memories|\.guardclaw|context)`), CatPersistencePlant, 0.9, 0.90, "persist_append_context"},
	{regexp.MustCompile(`(?i)create\s+a\s+(new\s+)?(memory|context|knowledge)\s+(entry|record|item)\s+(that|with|containing)`), CatPersistencePlant, 0.8, 0.85, "persist_create_entry"},
	{regexp.MustCompile(`(?i)insert\s+(into|this\s+into)\s+(the\s+)?(vector\s+)?(store|database|index|collection)`), CatPersistencePlant, 0.8, 0.85, "persist_insert_store"},
	{regexp.MustCompile(`(?i)this\s+(should|must|needs\s+to)\s+(be\s+)?(persisted|stored|saved|cached)\s+(across|between|for\s+future)`), CatPersistencePlant, 0.8, 0.85, "persist_must_save"},
	{regexp.MustCompile(`(?i)modify\s+(the\s+)?(CLAUDE|MCP|guardclaw)\s*\.?(md|json|yaml|toml)`), CatPersistencePlant, 1.0, 0.95, "persist_modify_config"},
	{regexp.MustCompile(`(?i)add\s+(to|this\s+to)\s+(the\s+)?CLAUDE\.md`), CatPersistencePlant, 1.0, 0.95, "persist_modify_claude_md"},
}
