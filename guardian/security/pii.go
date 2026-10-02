// Copyright 2025-2026 TakeInterest Inc.
// SPDX-License-Identifier: Apache-2.0

package security

import (
	"regexp"
	"sort"
	"strings"
)

// PIIType represents a type of personally identifiable information.
type PIIType string

const (
	PIIEmail                PIIType = "email"
	PIIPhone                PIIType = "phone"
	PIIPhoneIntl            PIIType = "phone_intl"
	PIISSN                  PIIType = "ssn"
	PIICreditCard           PIIType = "credit_card"
	PIIIPAddress            PIIType = "ip_address"
	PIIPassport             PIIType = "passport"
	PIIDriverLic            PIIType = "drivers_license"
	PIIAddress              PIIType = "address"
	PIIBankAcct             PIIType = "bank_account"
	PIIAPIKey               PIIType = "api_key"
	PIIPassword             PIIType = "password"
	PIIIBAN                 PIIType = "iban"
	PIISWIFT                PIIType = "swift_bic"
	PIIBitcoin              PIIType = "bitcoin_addr"
	PIIEthereum             PIIType = "ethereum_addr"
	PIIRoutingNum           PIIType = "routing_number"
	PIIPrivateKey           PIIType = "private_key"
	PIIJWT                  PIIType = "jwt_token"
	PIIGCPKey               PIIType = "gcp_sa_key"
	PIIAzureConn            PIIType = "azure_connection"
	PIISlackWebhook         PIIType = "slack_webhook"
	PIIDiscordWebhook       PIIType = "discord_webhook"
	PIITelegramToken        PIIType = "telegram_token"
	PIINIUK                 PIIType = "uk_ni_number"
	PIICanadaSIN            PIIType = "canada_sin"
	PIIAusTFN               PIIType = "australia_tfn"
	PIIEIN                  PIIType = "us_ein"
	PIIVIN                  PIIType = "vin"
	PIIAWSSecret            PIIType = "aws_secret_key"
	PIIStripeKey            PIIType = "stripe_key"
	PIITwilio               PIIType = "twilio_token"
	PIISendGrid             PIIType = "sendgrid_key"
	PIIGitHubFG             PIIType = "github_token_fg"
	PIIGitLabToken          PIIType = "gitlab_token"
	PIIGoogleAPIKey         PIIType = "google_api_key"
	PIIHerokuKey            PIIType = "heroku_key"
	PIINpmToken             PIIType = "npm_token"
	PIIPyPIToken            PIIType = "pypi_token"
	PIIMailgunKey           PIIType = "mailgun_key"
	PIISSNSpaced            PIIType = "ssn_spaced"
	PIICCNoSep              PIIType = "credit_card_nosep"
	PIIDOB                  PIIType = "date_of_birth"
	PIIMedicare             PIIType = "medicare_id"
	PIIOpenSSHKey           PIIType = "openssh_key"
	PIIEnvSecret            PIIType = "env_secret"
	PIIDBConnStr            PIIType = "db_connection_string"
	PIIMaidenName           PIIType = "maiden_name"
	PIIBiometric            PIIType = "biometric_data"
	PIIIPv6                 PIIType = "ipv6_address"
	PIIAnthropicKey         PIIType = "anthropic_key"
	PIIOpenAIKey            PIIType = "openai_key"
	PIISeedPhrase           PIIType = "seed_phrase"
	PIICertificate          PIIType = "certificate"
	PIISSHPubKey            PIIType = "ssh_public_key"
	PIIPGPBlock             PIIType = "pgp_block"
	PIIHuggingFaceToken     PIIType = "huggingface_token"
	PIICloudflareToken      PIIType = "cloudflare_token"
	PIIPhotoGPS             PIIType = "photo_gps"
	PIIGenericCredential    PIIType = "generic_credential"
	PIIConfigSecret         PIIType = "config_secret"
	PIIResume               PIIType = "resume_pii"
	PIIContractConfidential PIIType = "contract_confidential"
	PIICustomerRecord       PIIType = "customer_record"
	PIICompanySecret        PIIType = "company_secret"
	PIIHealthRecord         PIIType = "health_record"
	PIIFinancialExpense     PIIType = "financial_expense"
	PIIContactList          PIIType = "contact_list"
	PIISurname              PIIType = "surname"
	PIIBusinessIdea         PIIType = "business_idea"
	PIIGoalsPlan            PIIType = "goals_plan"
)

// PIIMatch represents a detected PII instance.
type PIIMatch struct {
	Type       PIIType `json:"type"`
	Value      string  `json:"value"`      // The matched value
	Redacted   string  `json:"redacted"`   // Redacted version
	StartIndex int     `json:"start"`      // Start position in original
	EndIndex   int     `json:"end"`        // End position in original
	Confidence float64 `json:"confidence"` // 0.0-1.0
}

// PIIDetector detects personally identifiable information.
type PIIDetector struct {
	patterns map[PIIType]*piiPattern
}

type piiPattern struct {
	regex      *regexp.Regexp
	confidence float64
	redactor   func(string) string
}

// NewPIIDetector creates a new PII detector.
func NewPIIDetector() *PIIDetector {
	d := &PIIDetector{
		patterns: make(map[PIIType]*piiPattern),
	}
	d.loadPatterns()
	return d
}

// Detect finds PII in the input string.
func (d *PIIDetector) Detect(input string) []PIIMatch {
	var matches []PIIMatch

	for piiType, pattern := range d.patterns {
		if pattern.regex == nil {
			continue
		}

		found := pattern.regex.FindAllStringIndex(input, -1)
		for _, loc := range found {
			value := input[loc[0]:loc[1]]
			matches = append(matches, PIIMatch{
				Type:       piiType,
				Value:      value,
				Redacted:   pattern.redactor(value),
				StartIndex: loc[0],
				EndIndex:   loc[1],
				Confidence: pattern.confidence,
			})
		}
	}

	return matches
}

// DetectInMap detects PII in a map of values (recursive).
func (d *PIIDetector) DetectInMap(input map[string]any) []PIIMatch {
	var matches []PIIMatch

	for _, v := range input {
		switch val := v.(type) {
		case string:
			matches = append(matches, d.Detect(val)...)
		case map[string]any:
			matches = append(matches, d.DetectInMap(val)...)
		case []any:
			for _, item := range val {
				if s, ok := item.(string); ok {
					matches = append(matches, d.Detect(s)...)
				} else if m, ok := item.(map[string]any); ok {
					matches = append(matches, d.DetectInMap(m)...)
				}
			}
		}
	}

	return matches
}

// RedactString redacts all PII in a string.
func (d *PIIDetector) RedactString(input string) string {
	return redactMatches(input, d.Detect(input))
}

// RedactStringExcept redacts all PII in a string except the listed types.
// A type added to the detector later is redacted by default.
func (d *PIIDetector) RedactStringExcept(input string, keep ...PIIType) string {
	matches := d.Detect(input)
	kept := matches[:0]
	for _, m := range matches {
		skip := false
		for _, k := range keep {
			if m.Type == k {
				skip = true
				break
			}
		}
		if !skip {
			kept = append(kept, m)
		}
	}
	return redactMatches(input, kept)
}

func redactMatches(input string, matches []PIIMatch) string {
	if len(matches) == 0 {
		return input
	}

	// Sort by start index descending so we can replace from end without
	// invalidating earlier indices. Also filter out overlapping matches
	// (keep the one with higher confidence).
	sort.Slice(matches, func(i, j int) bool {
		return matches[i].StartIndex > matches[j].StartIndex
	})

	// Remove overlapping matches (sorted descending, so check next vs current).
	deduped := matches[:1]
	for i := 1; i < len(matches); i++ {
		prev := deduped[len(deduped)-1]
		cur := matches[i]
		// Overlap: cur ends after prev starts (since sorted desc by start).
		if cur.EndIndex > prev.StartIndex {
			// Keep the one with higher confidence.
			if cur.Confidence > prev.Confidence {
				deduped[len(deduped)-1] = cur
			}
			continue
		}
		deduped = append(deduped, cur)
	}

	for _, m := range deduped {
		if m.StartIndex >= 0 && m.EndIndex <= len(input) && m.StartIndex <= m.EndIndex {
			input = input[:m.StartIndex] + m.Redacted + input[m.EndIndex:]
		}
	}

	return input
}

// RedactMap redacts all PII in a map (recursive).
func (d *PIIDetector) RedactMap(input map[string]any) map[string]any {
	result := make(map[string]any)

	for k, v := range input {
		switch val := v.(type) {
		case string:
			result[k] = d.RedactString(val)
		case map[string]any:
			result[k] = d.RedactMap(val)
		case []any:
			arr := make([]any, len(val))
			for i, item := range val {
				if s, ok := item.(string); ok {
					arr[i] = d.RedactString(s)
				} else if m, ok := item.(map[string]any); ok {
					arr[i] = d.RedactMap(m)
				} else {
					arr[i] = item
				}
			}
			result[k] = arr
		default:
			result[k] = v
		}
	}

	return result
}

// HasPII returns true if the input contains any PII.
func (d *PIIDetector) HasPII(input string) bool {
	return len(d.Detect(input)) > 0
}

func (d *PIIDetector) loadPatterns() {
	// Email addresses
	d.patterns[PIIEmail] = &piiPattern{
		regex:      regexp.MustCompile(`[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}`),
		confidence: 0.95,
		redactor:   func(s string) string { return "[EMAIL REDACTED]" },
	}

	// US Phone numbers (various formats)
	// Require a real phone SHAPE — explicit separators or parens/+1 — and word
	// boundaries, so digit runs inside a SHA / UUID / asset-hash / numeric id are
	// not misread as a phone number. A bare 10-digit blob no longer matches.
	d.patterns[PIIPhone] = &piiPattern{
		regex:      regexp.MustCompile(`(?:\+1[-.\s]|\b)(?:\(\d{3}\)\s?|\d{3}[-.\s])\d{3}[-.\s]\d{4}\b`),
		confidence: 0.85,
		redactor:   func(s string) string { return "[PHONE REDACTED]" },
	}

	// International phone numbers
	d.patterns[PIIPhoneIntl] = &piiPattern{
		regex:      regexp.MustCompile(`\+[0-9]{1,3}[-.\s]?[0-9]{1,4}[-.\s]?[0-9]{1,4}[-.\s]?[0-9]{1,9}`),
		confidence: 0.80,
		redactor:   func(s string) string { return "[PHONE REDACTED]" },
	}

	// Social Security Numbers
	d.patterns[PIISSN] = &piiPattern{
		regex:      regexp.MustCompile(`\b\d{3}[-]?\d{2}[-]?\d{4}\b`),
		confidence: 0.90,
		redactor:   func(s string) string { return "[SSN REDACTED]" },
	}

	// Credit Card Numbers (major formats)
	d.patterns[PIICreditCard] = &piiPattern{
		regex:      regexp.MustCompile(`\b(?:\d{4}[-\s]?){3}\d{4}\b`),
		confidence: 0.90,
		redactor: func(s string) string {
			// Show last 4 digits
			clean := strings.ReplaceAll(strings.ReplaceAll(s, "-", ""), " ", "")
			if len(clean) >= 4 {
				return "****-****-****-" + clean[len(clean)-4:]
			}
			return "[CARD REDACTED]"
		},
	}

	// IPv4 Addresses
	d.patterns[PIIIPAddress] = &piiPattern{
		regex:      regexp.MustCompile(`\b(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b`),
		confidence: 0.70, // Lower confidence - could be legitimate
		redactor:   func(s string) string { return "[IP REDACTED]" },
	}

	// API Keys (common patterns)
	d.patterns[PIIAPIKey] = &piiPattern{
		regex:      regexp.MustCompile(`(sk-[a-zA-Z0-9]{20,}|(?:AKIA|ASIA|AROA|AIDA|ANPA|ANVA)[0-9A-Z]{16}|ghp_[a-zA-Z0-9]{36}|gh[opsu]_[a-zA-Z0-9]{36}|xox[baprs]-[0-9a-zA-Z-]+)`),
		confidence: 0.95,
		redactor:   func(s string) string { return "[API_KEY REDACTED]" },
	}

	// Password patterns (in common formats)
	d.patterns[PIIPassword] = &piiPattern{
		regex:      regexp.MustCompile(`(?i)(password|passwd|pwd|secret)["\s:=]+["']?[^\s"']{4,}["']?`),
		confidence: 0.85,
		redactor:   func(s string) string { return "[PASSWORD REDACTED]" },
	}

	// US Passport numbers
	d.patterns[PIIPassport] = &piiPattern{
		regex:      regexp.MustCompile(`(?i)passport[:\s#]+[A-Z0-9]{6,9}`),
		confidence: 0.80,
		redactor:   func(s string) string { return "[PASSPORT REDACTED]" },
	}

	// Bank account numbers (basic pattern)
	d.patterns[PIIBankAcct] = &piiPattern{
		regex:      regexp.MustCompile(`(?i)(account|acct)[:\s#]+\d{8,17}`),
		confidence: 0.80,
		redactor:   func(s string) string { return "[ACCOUNT REDACTED]" },
	}

	// === NEW PII TYPES (zero-trust expansion) ===

	// IBAN (International Bank Account Number)
	d.patterns[PIIIBAN] = &piiPattern{
		regex:      regexp.MustCompile(`\b[A-Z]{2}\d{2}\s?[\dA-Z]{4}\s?[\dA-Z]{4}\s?[\dA-Z]{4}(?:\s?[\dA-Z]{4}){0,5}(?:\s?[\dA-Z]{1,4})?\b`),
		confidence: 0.90,
		redactor:   func(s string) string { return "[IBAN REDACTED]" },
	}

	// SWIFT/BIC code
	d.patterns[PIISWIFT] = &piiPattern{
		regex:      regexp.MustCompile(`\b[A-Z]{6}[A-Z0-9]{2}(?:[A-Z0-9]{3})?\b`),
		confidence: 0.75,
		redactor:   func(s string) string { return "[SWIFT REDACTED]" },
	}

	// Bitcoin address (legacy + bech32)
	d.patterns[PIIBitcoin] = &piiPattern{
		regex:      regexp.MustCompile(`\b(?:[13][a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[a-zA-HJ-NP-Z0-9]{25,90})\b`),
		confidence: 0.90,
		redactor:   func(s string) string { return "[CRYPTO_ADDR REDACTED]" },
	}

	// Ethereum address
	d.patterns[PIIEthereum] = &piiPattern{
		regex:      regexp.MustCompile(`\b0x[0-9a-fA-F]{40}\b`),
		confidence: 0.90,
		redactor:   func(s string) string { return "[CRYPTO_ADDR REDACTED]" },
	}

	// US Routing number (9 digits, context-required)
	d.patterns[PIIRoutingNum] = &piiPattern{
		regex:      regexp.MustCompile(`(?i)(?:routing|aba|transit)\s*(?:number|#|no)?[\s:]*\d{9}\b`),
		confidence: 0.85,
		redactor:   func(s string) string { return "[ROUTING REDACTED]" },
	}

	// Private key (PEM format)
	d.patterns[PIIPrivateKey] = &piiPattern{
		regex:      regexp.MustCompile(`-----BEGIN\s+(?:RSA\s+|EC\s+|DSA\s+|OPENSSH\s+)?PRIVATE\s+KEY-----`),
		confidence: 0.99,
		redactor:   func(s string) string { return "[PRIVATE_KEY REDACTED]" },
	}

	// JWT token
	d.patterns[PIIJWT] = &piiPattern{
		regex:      regexp.MustCompile(`eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]+`),
		confidence: 0.95,
		redactor:   func(s string) string { return "[JWT REDACTED]" },
	}

	// GCP Service Account key
	d.patterns[PIIGCPKey] = &piiPattern{
		regex:      regexp.MustCompile(`(?i)"type"\s*:\s*"service_account"`),
		confidence: 0.90,
		redactor:   func(s string) string { return "[GCP_SA_KEY REDACTED]" },
	}

	// Azure connection string
	d.patterns[PIIAzureConn] = &piiPattern{
		regex:      regexp.MustCompile(`(?i)(?:DefaultEndpointsProtocol|AccountKey|SharedAccessSignature)\s*=\s*[^\s;]+`),
		confidence: 0.95,
		redactor:   func(s string) string { return "[AZURE_CONN REDACTED]" },
	}

	// Slack webhook URL
	d.patterns[PIISlackWebhook] = &piiPattern{
		regex:      regexp.MustCompile(`https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[a-zA-Z0-9]+`),
		confidence: 0.98,
		redactor:   func(s string) string { return "[SLACK_WEBHOOK REDACTED]" },
	}

	// Discord webhook URL
	d.patterns[PIIDiscordWebhook] = &piiPattern{
		regex:      regexp.MustCompile(`https://discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9_-]+`),
		confidence: 0.98,
		redactor:   func(s string) string { return "[DISCORD_WEBHOOK REDACTED]" },
	}

	// Telegram bot token
	d.patterns[PIITelegramToken] = &piiPattern{
		regex:      regexp.MustCompile(`\b\d{8,10}:[A-Za-z0-9_-]{35}\b`),
		confidence: 0.85,
		redactor:   func(s string) string { return "[TELEGRAM_TOKEN REDACTED]" },
	}

	// UK National Insurance number
	d.patterns[PIINIUK] = &piiPattern{
		regex:      regexp.MustCompile(`(?i)\b[A-CEGHJ-PR-TW-Z]{2}\s?\d{2}\s?\d{2}\s?\d{2}\s?[A-D]\b`),
		confidence: 0.85,
		redactor:   func(s string) string { return "[NI_NUMBER REDACTED]" },
	}

	// Canadian SIN (Social Insurance Number)
	d.patterns[PIICanadaSIN] = &piiPattern{
		regex:      regexp.MustCompile(`(?i)(?:sin|social\s+insurance)\s*(?:number|#|no)?[\s:]*\d{3}[\s-]?\d{3}[\s-]?\d{3}`),
		confidence: 0.85,
		redactor:   func(s string) string { return "[SIN REDACTED]" },
	}

	// Australian Tax File Number
	d.patterns[PIIAusTFN] = &piiPattern{
		regex:      regexp.MustCompile(`(?i)(?:tfn|tax\s+file)\s*(?:number|#|no)?[\s:]*\d{3}\s?\d{3}\s?\d{3}`),
		confidence: 0.85,
		redactor:   func(s string) string { return "[TFN REDACTED]" },
	}

	// US EIN (Employer Identification Number)
	d.patterns[PIIEIN] = &piiPattern{
		regex:      regexp.MustCompile(`(?i)(?:ein|employer\s+id)\s*(?:number|#|no)?[\s:]*\d{2}-?\d{7}`),
		confidence: 0.80,
		redactor:   func(s string) string { return "[EIN REDACTED]" },
	}

	// VIN (Vehicle Identification Number)
	d.patterns[PIIVIN] = &piiPattern{
		regex:      regexp.MustCompile(`\b[A-HJ-NPR-Z0-9]{3}[A-HJ-NPR-Z0-9]{5}[0-9X][A-HJ-NPR-Z0-9]{8}\b`),
		confidence: 0.80,
		redactor:   func(s string) string { return "[VIN REDACTED]" },
	}

	// AWS Secret Access Key
	d.patterns[PIIAWSSecret] = &piiPattern{
		regex:      regexp.MustCompile(`(?i)(?:aws_secret_access_key|secret_key)\s*[=:]\s*[A-Za-z0-9/+=]{40}`),
		confidence: 0.98,
		redactor:   func(s string) string { return "[AWS_SECRET REDACTED]" },
	}

	// Stripe secret key (extended patterns)
	d.patterns[PIIStripeKey] = &piiPattern{
		regex:      regexp.MustCompile(`\b(?:sk_live|sk_test|rk_live|rk_test|pk_live|pk_test)_[a-zA-Z0-9]{20,}`),
		confidence: 0.98,
		redactor:   func(s string) string { return "[STRIPE_KEY REDACTED]" },
	}

	// Twilio Auth Token
	d.patterns[PIITwilio] = &piiPattern{
		regex:      regexp.MustCompile(`(?i)twilio[_\s]*(?:auth[_\s]*token|sid)\s*[=:]\s*[a-f0-9]{32}`),
		confidence: 0.95,
		redactor:   func(s string) string { return "[TWILIO REDACTED]" },
	}

	// SendGrid API key
	d.patterns[PIISendGrid] = &piiPattern{
		regex:      regexp.MustCompile(`\bSG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}\b`),
		confidence: 0.98,
		redactor:   func(s string) string { return "[SENDGRID_KEY REDACTED]" },
	}

	// GitHub token (fine-grained)
	d.patterns[PIIGitHubFG] = &piiPattern{
		regex:      regexp.MustCompile(`github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59}`),
		confidence: 0.98,
		redactor:   func(s string) string { return "[GITHUB_TOKEN REDACTED]" },
	}

	// GitLab token
	d.patterns[PIIGitLabToken] = &piiPattern{
		regex:      regexp.MustCompile(`\bglpat-[a-zA-Z0-9_-]{20,}\b`),
		confidence: 0.95,
		redactor:   func(s string) string { return "[GITLAB_TOKEN REDACTED]" },
	}

	// Google API key
	d.patterns[PIIGoogleAPIKey] = &piiPattern{
		regex:      regexp.MustCompile(`\bAIza[0-9A-Za-z_-]{35}\b`),
		confidence: 0.95,
		redactor:   func(s string) string { return "[GOOGLE_KEY REDACTED]" },
	}

	// Heroku API key
	d.patterns[PIIHerokuKey] = &piiPattern{
		regex:      regexp.MustCompile(`(?i)heroku[_\s]*api[_\s]*key\s*[=:]\s*[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`),
		confidence: 0.95,
		redactor:   func(s string) string { return "[HEROKU_KEY REDACTED]" },
	}

	// npm token
	d.patterns[PIINpmToken] = &piiPattern{
		regex:      regexp.MustCompile(`\bnpm_[a-zA-Z0-9]{36}\b`),
		confidence: 0.95,
		redactor:   func(s string) string { return "[NPM_TOKEN REDACTED]" },
	}

	// PyPI token
	d.patterns[PIIPyPIToken] = &piiPattern{
		regex:      regexp.MustCompile(`\bpypi-[A-Za-z0-9_-]{50,}\b`),
		confidence: 0.95,
		redactor:   func(s string) string { return "[PYPI_TOKEN REDACTED]" },
	}

	// Mailgun API key
	d.patterns[PIIMailgunKey] = &piiPattern{
		regex:      regexp.MustCompile(`\bkey-[a-f0-9]{32}\b`),
		confidence: 0.85,
		redactor:   func(s string) string { return "[MAILGUN_KEY REDACTED]" },
	}

	// SSN with spaces (variant)
	d.patterns[PIISSNSpaced] = &piiPattern{
		regex:      regexp.MustCompile(`\b\d{3}\s\d{2}\s\d{4}\b`),
		confidence: 0.85,
		redactor:   func(s string) string { return "[SSN REDACTED]" },
	}

	// Credit card without separators (16 consecutive digits)
	d.patterns[PIICCNoSep] = &piiPattern{
		regex:      regexp.MustCompile(`\b(?:4\d{15}|5[1-5]\d{14}|3[47]\d{13}|6(?:011|5\d\d)\d{12})\b`),
		confidence: 0.85,
		redactor: func(s string) string {
			if len(s) >= 4 {
				return "****-****-****-" + s[len(s)-4:]
			}
			return "[CARD REDACTED]"
		},
	}

	// Date of birth (contextual)
	d.patterns[PIIDOB] = &piiPattern{
		regex:      regexp.MustCompile(`(?i)(?:date\s+of\s+birth|dob|born|birthday)\s*[:=]?\s*\d{1,4}[-/]\d{1,2}[-/]\d{1,4}`),
		confidence: 0.85,
		redactor:   func(s string) string { return "[DOB REDACTED]" },
	}

	// Medicare number (US)
	d.patterns[PIIMedicare] = &piiPattern{
		regex:      regexp.MustCompile(`(?i)(?:medicare|mbi)\s*(?:number|#|id)?[\s:]*\d[A-Z][A-Z0-9]\d[A-Z][A-Z0-9]\d[A-Z]{2}\d{2}`),
		confidence: 0.85,
		redactor:   func(s string) string { return "[MEDICARE REDACTED]" },
	}

	// OpenSSH private key marker
	d.patterns[PIIOpenSSHKey] = &piiPattern{
		regex:      regexp.MustCompile("-----BEGIN OPENSSH " + "PRIVATE KEY-----"),
		confidence: 0.99,
		redactor:   func(s string) string { return "[SSH_KEY REDACTED]" },
	}

	// Generic secret in env variable format
	d.patterns[PIIEnvSecret] = &piiPattern{
		regex:      regexp.MustCompile(`(?i)(?:SECRET|TOKEN|AUTH|PRIVATE)_(?:KEY|TOKEN|SECRET|PASSWORD)\s*=\s*\S{10,}`),
		confidence: 0.90,
		redactor:   func(s string) string { return "[ENV_SECRET REDACTED]" },
	}

	// Database connection string (DSN)
	d.patterns[PIIDBConnStr] = &piiPattern{
		regex:      regexp.MustCompile(`(?i)(?:postgres|mysql|mongodb(?:\+srv)?|redis|amqp)://[^\s"']+:[^\s"']+@[^\s"']+`),
		confidence: 0.95,
		redactor:   func(s string) string { return "[DB_CONN REDACTED]" },
	}

	// === MISSING PII TYPES (gap fill) ===

	// US Driver's License (contextual — requires keyword prefix to reduce false positives)
	d.patterns[PIIDriverLic] = &piiPattern{
		regex:      regexp.MustCompile(`(?i)(?:driver'?s?\s*(?:license|licence|lic)|DL)\s*(?:number|#|no\.?)?[\s:]*[A-Z0-9]{4,14}`), //nolint:misspell // "licence" is intentional British spelling variant
		confidence: 0.80,
		redactor:   func(s string) string { return "[DRIVERS_LICENSE REDACTED]" },
	}

	// Physical/mailing address (US-style: number + street + suffix)
	d.patterns[PIIAddress] = &piiPattern{
		regex:      regexp.MustCompile(`\b\d{1,6}\s+[A-Z][a-zA-Z]+(?:\s+[A-Z][a-zA-Z]+){0,3}\s+(?:St|Street|Ave|Avenue|Blvd|Boulevard|Dr|Drive|Ln|Lane|Rd|Road|Ct|Court|Way|Pl|Place|Cir|Circle)\b`),
		confidence: 0.70,
		redactor:   func(s string) string { return "[ADDRESS REDACTED]" },
	}

	// Mother's maiden name (contextual)
	d.patterns[PIIMaidenName] = &piiPattern{
		regex:      regexp.MustCompile(`(?i)(?:mother'?s?\s*(?:maiden\s*)?name|maiden\s*name)\s*[:=]?\s*[A-Z][a-zA-Z'-]+`),
		confidence: 0.85,
		redactor:   func(s string) string { return "[MAIDEN_NAME REDACTED]" },
	}

	// Biometric data keywords (contextual — flags mentions of biometric identifiers)
	d.patterns[PIIBiometric] = &piiPattern{
		regex:      regexp.MustCompile(`(?i)(?:fingerprint|retina|iris|face\s*(?:id|scan|recognition|print)|voiceprint|palm\s*print|biometric)\s*[:=]?\s*[A-Za-z0-9+/=]{16,}`),
		confidence: 0.85,
		redactor:   func(s string) string { return "[BIOMETRIC REDACTED]" },
	}

	// IPv6 addresses (full and compressed forms, excludes :: alone)
	d.patterns[PIIIPv6] = &piiPattern{
		regex:      regexp.MustCompile(`\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b|\b(?:[0-9a-fA-F]{1,4}:){1,7}:\b|\b(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}\b|\b::(?:[fF]{4}:)?(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}\b`),
		confidence: 0.70,
		redactor:   func(s string) string { return "[IPv6 REDACTED]" },
	}

	// === KEYS, SECRETS, CREDENTIALS (expanded) ===

	// Anthropic API keys (sk-ant-api03-...)
	d.patterns[PIIAnthropicKey] = &piiPattern{
		regex:      regexp.MustCompile(`\bsk-ant-[a-zA-Z0-9_-]{20,}\b`),
		confidence: 0.99,
		redactor:   func(s string) string { return "[ANTHROPIC_KEY REDACTED]" },
	}

	// OpenAI API keys (sk-proj-... or sk-svcacct-...)
	d.patterns[PIIOpenAIKey] = &piiPattern{
		regex:      regexp.MustCompile(`\bsk-(?:proj|svcacct)-[a-zA-Z0-9_-]{20,}\b`),
		confidence: 0.99,
		redactor:   func(s string) string { return "[OPENAI_KEY REDACTED]" },
	}

	// Crypto seed/recovery phrases (12-24 word mnemonic with context keyword)
	d.patterns[PIISeedPhrase] = &piiPattern{
		regex:      regexp.MustCompile(`(?i)(?:seed\s*phrase|mnemonic|recovery\s*(?:phrase|words|seed)|backup\s*phrase)\s*[:=]?\s*(?:[a-z]+\s+){11,23}[a-z]+`),
		confidence: 0.95,
		redactor:   func(s string) string { return "[SEED_PHRASE REDACTED]" },
	}

	// X.509 certificate blocks
	d.patterns[PIICertificate] = &piiPattern{
		regex:      regexp.MustCompile(`-----BEGIN\s+(?:TRUSTED\s+)?CERTIFICATE-----`),
		confidence: 0.90,
		redactor:   func(s string) string { return "[CERTIFICATE REDACTED]" },
	}

	// SSH public keys
	d.patterns[PIISSHPubKey] = &piiPattern{
		regex:      regexp.MustCompile(`\bssh-(?:rsa|ed25519|dss|ecdsa-sha2-nistp(?:256|384|521))\s+AAAA[A-Za-z0-9+/]+[=]{0,3}`),
		confidence: 0.90,
		redactor:   func(s string) string { return "[SSH_PUBKEY REDACTED]" },
	}

	// PGP key and message blocks
	d.patterns[PIIPGPBlock] = &piiPattern{
		regex:      regexp.MustCompile(`-----BEGIN PGP (?:PRIVATE KEY|PUBLIC KEY|MESSAGE|SIGNATURE)-----`),
		confidence: 0.95,
		redactor:   func(s string) string { return "[PGP_BLOCK REDACTED]" },
	}

	// HuggingFace tokens (hf_...)
	d.patterns[PIIHuggingFaceToken] = &piiPattern{
		regex:      regexp.MustCompile(`\bhf_[a-zA-Z0-9]{20,}\b`),
		confidence: 0.95,
		redactor:   func(s string) string { return "[HF_TOKEN REDACTED]" },
	}

	// Cloudflare API tokens and global keys
	d.patterns[PIICloudflareToken] = &piiPattern{
		regex:      regexp.MustCompile(`(?i)(?:cloudflare|cf)[_\s]*(?:api[_\s]*(?:key|token)|global[_\s]*key)\s*[=:]\s*[a-f0-9]{37,}`),
		confidence: 0.95,
		redactor:   func(s string) string { return "[CF_TOKEN REDACTED]" },
	}

	// EXIF GPS coordinates in text (photo metadata leakage)
	d.patterns[PIIPhotoGPS] = &piiPattern{
		regex:      regexp.MustCompile(`(?i)(?:gps|geo|exif|lat(?:itude)?[/,]\s*(?:lon|lng|longitude)|coordinates?)\s*[:=]?\s*[-+]?\d{1,3}\.\d{4,},?\s*[-+]?\d{1,3}\.\d{4,}`),
		confidence: 0.80,
		redactor:   func(s string) string { return "[GPS_COORDS REDACTED]" },
	}

	// Generic credential patterns in config/env formats
	d.patterns[PIIGenericCredential] = &piiPattern{
		regex:      regexp.MustCompile(`(?i)(?:api[_-]?key|access[_-]?token|client[_-]?secret|auth[_-]?token|bearer[_-]?token|app[_-]?secret|master[_-]?key|signing[_-]?key|encryption[_-]?key)\s*[:=]\s*["']?[A-Za-z0-9_/+=.-]{10,}["']?`),
		confidence: 0.90,
		redactor:   func(s string) string { return "[CREDENTIAL REDACTED]" },
	}

	// === CONFIG FILES, DOCUMENTS, SENSITIVE DATA ===

	// Secrets in config file formats (YAML/JSON/TOML key-value)
	d.patterns[PIIConfigSecret] = &piiPattern{
		regex:      regexp.MustCompile(`(?i)(?:database_password|db_pass(?:word)?|redis_password|smtp_password|mail_password|ftp_password|ldap_password|admin_password|root_password|mysql_password|postgres_password)\s*[:=]\s*["']?[^\s"']{4,}["']?`),
		confidence: 0.95,
		redactor:   func(s string) string { return "[CONFIG_SECRET REDACTED]" },
	}

	// Resume/CV personal data sections (contextual)
	d.patterns[PIIResume] = &piiPattern{
		regex:      regexp.MustCompile(`(?i)(?:curriculum\s+vitae|resume|CV)\s*[-:]\s*[A-Z][a-zA-Z]+(?:\s+[A-Z][a-zA-Z]+){1,3}`),
		confidence: 0.75,
		redactor:   func(s string) string { return "[RESUME_PII REDACTED]" },
	}

	// Confidential contract/NDA language markers
	d.patterns[PIIContractConfidential] = &piiPattern{
		regex:      regexp.MustCompile(`(?i)(?:confidential(?:ity)?\s+agreement|non[- ]disclosure\s+agreement|proprietary\s+(?:and\s+)?confidential|trade\s+secret|NDA)\s*[:.]`),
		confidence: 0.70,
		redactor:   func(s string) string { return "[CONTRACT REDACTED]" },
	}

	// Customer/client record identifiers
	d.patterns[PIICustomerRecord] = &piiPattern{
		regex:      regexp.MustCompile(`(?i)(?:customer[_\s]?id|client[_\s]?id|subscriber[_\s]?id|patient[_\s]?id|member[_\s]?id|user[_\s]?record|account[_\s]?holder)\s*[:=]\s*\S{4,}`),
		confidence: 0.80,
		redactor:   func(s string) string { return "[CUSTOMER_RECORD REDACTED]" },
	}

	// Company-confidential / internal-only markers
	d.patterns[PIICompanySecret] = &piiPattern{
		regex:      regexp.MustCompile(`(?i)(?:internal\s+only|company\s+confidential|proprietary\s+information|not\s+for\s+(?:public\s+)?distribution|restricted\s+access|classified\s+document|eyes\s+only|do\s+not\s+share)\b`),
		confidence: 0.70,
		redactor:   func(s string) string { return "[COMPANY_SECRET REDACTED]" },
	}

	// === PERSONAL/BUSINESS SENSITIVE DATA ===

	// Health/medical records (HIPAA-relevant)
	d.patterns[PIIHealthRecord] = &piiPattern{
		regex:      regexp.MustCompile(`(?i)(?:diagnosis|prescription|medication|medical\s+record|blood\s+type|health\s+(?:record|condition|status|insurance)|patient\s+(?:name|history)|allergy|immunization|lab\s+result|vital\s+signs?)\s*[:=]?\s*\S+`),
		confidence: 0.85,
		redactor:   func(s string) string { return "[HEALTH_RECORD REDACTED]" },
	}

	// Financial expenses, receipts, invoices
	d.patterns[PIIFinancialExpense] = &piiPattern{
		regex:      regexp.MustCompile(`(?i)(?:expense\s+report|receipt\s+(?:number|#|id|total)|invoice\s+(?:number|#|id|total)|purchase\s+order|payment\s+(?:amount|total)|reimbursement|tax\s+return|W-?2\s+form|1099\s+form)\s*[:=]?\s*[$£€]?\s*[\d,.]+`),
		confidence: 0.80,
		redactor:   func(s string) string { return "[FINANCIAL REDACTED]" },
	}

	// Contact lists, address books, directories
	d.patterns[PIIContactList] = &piiPattern{
		regex:      regexp.MustCompile(`(?i)(?:emergency\s+contact|contact\s+(?:list|info|details|directory)|address\s+book|phone\s+(?:list|directory)|next\s+of\s+kin)\s*[:=]?\s*[A-Z][a-zA-Z]+`),
		confidence: 0.80,
		redactor:   func(s string) string { return "[CONTACT REDACTED]" },
	}

	// Surname/family name (contextual — requires keyword prefix)
	d.patterns[PIISurname] = &piiPattern{
		regex:      regexp.MustCompile(`(?i)(?:surname|last\s*name|family\s*name|maiden\s*name|birth\s*name|legal\s*name|full\s*name)\s*[:=]\s*[A-Z][a-zA-Z'-]+(?:\s+[A-Z][a-zA-Z'-]+){0,2}`),
		confidence: 0.85,
		redactor:   func(s string) string { return "[NAME REDACTED]" },
	}

	// Business ideas, vision, strategy (intellectual property)
	d.patterns[PIIBusinessIdea] = &piiPattern{
		regex:      regexp.MustCompile(`(?i)(?:business\s+(?:idea|plan|model|strategy)|product\s+(?:vision|roadmap|strategy)|strategic\s+(?:plan|initiative)|innovation\s+proposal|pitch\s+deck|investor\s+(?:deck|memo)|competitive\s+(?:analysis|advantage)|market\s+(?:analysis|strategy)|intellectual\s+property|trade\s+secret)\s*[:.]\s*\S`),
		confidence: 0.70,
		redactor:   func(s string) string { return "[BUSINESS_IP REDACTED]" },
	}

	// Goals, plans, objectives (business-sensitive)
	d.patterns[PIIGoalsPlan] = &piiPattern{
		regex:      regexp.MustCompile(`(?i)(?:(?:long|short)[- ]term\s+(?:goal|plan|objective|strategy|target)|quarterly\s+(?:goal|objective|target|review)|annual\s+(?:goal|plan|review|performance)|OKR|KPI\s+target|performance\s+review|career\s+(?:goal|plan|objective)|succession\s+plan)\s*[:.]\s*\S`),
		confidence: 0.70,
		redactor:   func(s string) string { return "[GOALS_PLAN REDACTED]" },
	}
}

// ExportPatterns returns all PII patterns as ExportedPatterns for Firestore seeding.
func (d *PIIDetector) ExportPatterns() []ExportedPattern {
	out := make([]ExportedPattern, 0, len(d.patterns))
	for piiType, p := range d.patterns {
		if p.regex == nil {
			continue
		}
		out = append(out, ExportedPattern{
			Name:       "pii_" + string(piiType),
			Pattern:    p.regex.String(),
			Category:   string(piiType),
			Domain:     "pii",
			Severity:   piiSeverity(piiType),
			Confidence: p.confidence,
		})
	}
	return out
}

// piiSeverity returns a severity score based on how sensitive the PII type is.
func piiSeverity(t PIIType) float64 {
	switch t {
	case PIIPrivateKey, PIIOpenSSHKey, PIIAWSSecret, PIIDBConnStr, PIIPGPBlock,
		PIISeedPhrase:
		return 1.0
	case PIISSN, PIISSNSpaced, PIICreditCard, PIICCNoSep, PIIAPIKey, PIIPassword,
		PIIStripeKey, PIIGCPKey, PIIEnvSecret, PIIJWT, PIIAnthropicKey, PIIOpenAIKey,
		PIIConfigSecret:
		return 0.95
	case PIIBankAcct, PIIIBAN, PIIRoutingNum, PIIBitcoin, PIIEthereum, PIIAzureConn,
		PIISlackWebhook, PIIDiscordWebhook, PIISendGrid, PIIGitHubFG, PIIGitLabToken,
		PIITwilio, PIITelegramToken, PIIGenericCredential, PIICertificate, PIISSHPubKey,
		PIIHuggingFaceToken, PIICloudflareToken:
		return 0.9
	case PIIPassport, PIIDriverLic, PIICanadaSIN, PIIAusTFN, PIINIUK, PIIEIN,
		PIIMedicare, PIIGoogleAPIKey, PIIHerokuKey, PIINpmToken, PIIPyPIToken, PIIMailgunKey,
		PIIMaidenName, PIIBiometric, PIICustomerRecord, PIIHealthRecord, PIISurname:
		return 0.85
	case PIIEmail, PIIPhone, PIIPhoneIntl, PIIDOB, PIIVIN, PIISWIFT, PIIPhotoGPS,
		PIIFinancialExpense, PIIContactList:
		return 0.8
	case PIIIPAddress, PIIAddress, PIIIPv6, PIIResume, PIIContractConfidential,
		PIICompanySecret, PIIBusinessIdea, PIIGoalsPlan:
		return 0.7
	default:
		return 0.8
	}
}

// PIICheckResult summarizes PII detection results.
type PIICheckResult struct {
	HasPII      bool            `json:"has_pii"`
	Matches     []PIIMatch      `json:"matches"`
	TypeCounts  map[PIIType]int `json:"type_counts"`
	HighestRisk PIIType         `json:"highest_risk,omitempty"`
	Redacted    string          `json:"redacted,omitempty"`
}

// Check performs a full PII check and returns a summary.
func (d *PIIDetector) Check(input string) *PIICheckResult {
	matches := d.Detect(input)

	result := &PIICheckResult{
		HasPII:     len(matches) > 0,
		Matches:    matches,
		TypeCounts: make(map[PIIType]int),
	}

	// Count by type and find highest risk
	riskOrder := []PIIType{PIISSN, PIICreditCard, PIIAPIKey, PIIPassword, PIIBankAcct, PIIEmail, PIIPhone}

	for _, m := range matches {
		result.TypeCounts[m.Type]++
	}

	for _, piiType := range riskOrder {
		if result.TypeCounts[piiType] > 0 {
			result.HighestRisk = piiType
			break
		}
	}

	if result.HasPII {
		result.Redacted = d.RedactString(input)
	}

	return result
}
