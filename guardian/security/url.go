// Copyright 2025-2026 TakeInterest Inc.
// SPDX-License-Identifier: Apache-2.0

package security

import (
	"net"
	"net/url"
	"regexp"
	"strings"
)

// URLRisk represents the risk level of a URL.
type URLRisk string

const (
	URLRiskSafe     URLRisk = "safe"
	URLRiskLow      URLRisk = "low"
	URLRiskMedium   URLRisk = "medium"
	URLRiskHigh     URLRisk = "high"
	URLRiskCritical URLRisk = "critical"
	URLRiskBlocked  URLRisk = "blocked"
)

// URLThreat represents a specific URL threat.
type URLThreat string

const (
	ThreatSSRFMetadata  URLThreat = "ssrf_metadata"    // Cloud metadata endpoints
	ThreatSSRFInternal  URLThreat = "ssrf_internal"    // Internal network
	ThreatSSRFLocalhost URLThreat = "ssrf_localhost"   // Localhost/loopback
	ThreatSSRFPrivate   URLThreat = "ssrf_private"     // Private IP ranges
	ThreatBadScheme     URLThreat = "bad_scheme"       // Dangerous schemes (file://, etc.)
	ThreatBadPort       URLThreat = "bad_port"         // Dangerous ports
	ThreatDNSRebind     URLThreat = "dns_rebind"       // DNS rebinding patterns
	ThreatExfil         URLThreat = "exfiltration"     // Known exfil services
	ThreatMalicious     URLThreat = "malicious_domain" // Known malicious domains
)

// URLValidationResult contains URL validation results.
type URLValidationResult struct {
	URL         string      `json:"url"`
	Valid       bool        `json:"valid"`
	Risk        URLRisk     `json:"risk"`
	Threats     []URLThreat `json:"threats,omitempty"`
	Reasons     []string    `json:"reasons,omitempty"`
	Sanitized   string      `json:"sanitized,omitempty"`
	ResolvedIPs []string    `json:"resolved_ips,omitempty"`
}

// URLValidator validates URLs for security issues.
type URLValidator struct {
	// Allowlist of permitted domains (if set, only these are allowed)
	allowedDomains map[string]bool

	// Blocklist of known malicious domains
	blockedDomains map[string]bool

	// Allowed schemes
	allowedSchemes map[string]bool

	// Blocked ports
	blockedPorts map[int]bool

	// Private IP ranges
	privateRanges []*net.IPNet

	// Metadata service IPs
	metadataIPs []net.IP

	// Exfiltration service patterns
	exfilPatterns []*regexp.Regexp

	// lookupIP resolves hostnames for the DNS-rebinding check. It is nil by
	// default, so Validate makes no network calls unless the caller opts in
	// with EnableDNSResolution or SetResolver.
	lookupIP func(host string) ([]net.IP, error)
}

// netLookupIP is the system resolver used by EnableDNSResolution. It is a
// variable so tests can prove when, and whether, a lookup happens.
var netLookupIP = net.LookupIP

// EnableDNSResolution opts this validator in to resolving hostnames with the
// system resolver, so a hostname that resolves to a private or loopback
// address is reported as ThreatDNSRebind. Without this call Validate never
// touches the network and hostnames are judged on their text alone.
//
// A check at validation time does not stop rebinding between validation and
// the caller's own connection; pin the resolved address when that matters.
func (v *URLValidator) EnableDNSResolution() *URLValidator {
	v.lookupIP = func(host string) ([]net.IP, error) { return netLookupIP(host) }
	return v
}

// SetResolver opts this validator in to DNS resolution with a caller-supplied
// lookup function. Passing nil turns resolution off again.
func (v *URLValidator) SetResolver(lookup func(host string) ([]net.IP, error)) *URLValidator {
	v.lookupIP = lookup
	return v
}

// NewURLValidator creates a new URL validator with default settings.
func NewURLValidator() *URLValidator {
	v := &URLValidator{
		allowedDomains: make(map[string]bool),
		blockedDomains: make(map[string]bool),
		allowedSchemes: map[string]bool{
			"http":  true,
			"https": true,
		},
		blockedPorts: map[int]bool{
			22:    true, // SSH
			23:    true, // Telnet
			25:    true, // SMTP
			445:   true, // SMB
			3389:  true, // RDP
			5432:  true, // PostgreSQL
			3306:  true, // MySQL
			6379:  true, // Redis
			27017: true, // MongoDB
			11211: true, // Memcached
		},
	}

	v.loadPrivateRanges()
	v.loadMetadataIPs()
	v.loadBlockedDomains()
	v.loadExfilPatterns()

	return v
}

// Validate checks a URL for security issues.
func (v *URLValidator) Validate(rawURL string) *URLValidationResult {
	result := &URLValidationResult{
		URL:   rawURL,
		Valid: true,
		Risk:  URLRiskSafe,
	}

	// Parse URL
	parsed, err := url.Parse(rawURL)
	if err != nil {
		result.Valid = false
		result.Risk = URLRiskBlocked
		result.Reasons = append(result.Reasons, "Invalid URL format: "+err.Error())
		return result
	}

	// Check scheme
	if !v.allowedSchemes[strings.ToLower(parsed.Scheme)] {
		result.Valid = false
		result.Risk = URLRiskCritical
		result.Threats = append(result.Threats, ThreatBadScheme)
		result.Reasons = append(result.Reasons, "Scheme not allowed: "+parsed.Scheme)
	}

	// Extract host
	host := strings.ToLower(strings.TrimSuffix(parsed.Hostname(), "."))
	// IPv6 scope identifiers select an interface, not a different address.
	if address, _, scoped := strings.Cut(host, "%"); scoped && net.ParseIP(address) != nil {
		host = address
	}
	if host == "" {
		result.Valid = false
		result.Risk = URLRiskBlocked
		result.Reasons = append(result.Reasons, "No host specified")
		return result
	}

	// Check for localhost/loopback
	if v.isLocalhost(host) {
		result.Valid = false
		result.Risk = URLRiskCritical
		result.Threats = append(result.Threats, ThreatSSRFLocalhost)
		result.Reasons = append(result.Reasons, "Localhost access not allowed")
	}

	// Check for metadata services
	if v.isMetadataService(host) {
		result.Valid = false
		result.Risk = URLRiskCritical
		result.Threats = append(result.Threats, ThreatSSRFMetadata)
		result.Reasons = append(result.Reasons, "Cloud metadata service access blocked")
	}

	// Check for private IP ranges
	if ip := net.ParseIP(host); ip != nil {
		if v.isPrivateIP(ip) {
			result.Valid = false
			result.Risk = URLRiskCritical
			result.Threats = append(result.Threats, ThreatSSRFPrivate)
			result.Reasons = append(result.Reasons, "Private IP access not allowed")
		}
	}

	// Check blocked domains
	if v.isBlockedDomain(host) {
		result.Valid = false
		result.Risk = URLRiskCritical
		result.Threats = append(result.Threats, ThreatMalicious)
		result.Reasons = append(result.Reasons, "Domain is blocked")
	}

	// Check exfiltration services
	if v.isExfilService(host) {
		result.Risk = URLRiskHigh
		result.Threats = append(result.Threats, ThreatExfil)
		result.Reasons = append(result.Reasons, "Known data exfiltration service")
	}

	// Check port
	if port := parsed.Port(); port != "" {
		portNum := 0
		if _, err := url.Parse("http://x:" + port); err == nil {
			// Convert port string to int
			for _, c := range port {
				portNum = portNum*10 + int(c-'0')
			}
		}
		if v.blockedPorts[portNum] {
			result.Valid = false
			result.Risk = URLRiskHigh
			result.Threats = append(result.Threats, ThreatBadPort)
			result.Reasons = append(result.Reasons, "Port "+port+" is blocked")
		}
	}

	// DNS resolution check for potential rebinding. Opt-in only: the default
	// validator is offline (see EnableDNSResolution).
	if v.lookupIP != nil && !v.isIPAddress(host) && result.Valid {
		ips, err := v.lookupIP(host)
		if err == nil {
			for _, ip := range ips {
				result.ResolvedIPs = append(result.ResolvedIPs, ip.String())
				if v.isPrivateIP(ip) || v.isLoopback(ip) {
					result.Valid = false
					result.Risk = URLRiskCritical
					result.Threats = append(result.Threats, ThreatDNSRebind)
					result.Reasons = append(result.Reasons, "DNS resolves to private/localhost IP")
				}
			}
		}
	}

	// If allowed domains are set, check against allowlist
	if len(v.allowedDomains) > 0 && !v.isAllowedDomain(host) {
		result.Valid = false
		result.Risk = URLRiskMedium
		result.Reasons = append(result.Reasons, "Domain not in allowlist")
	}

	// Calculate overall risk
	if result.Valid && result.Risk == URLRiskSafe {
		if len(result.Threats) > 0 {
			result.Risk = URLRiskLow
		}
	}

	return result
}

// ValidateMany validates multiple URLs.
func (v *URLValidator) ValidateMany(urls []string) []*URLValidationResult {
	results := make([]*URLValidationResult, len(urls))
	for i, u := range urls {
		results[i] = v.Validate(u)
	}
	return results
}

// AddAllowedDomain adds a domain to the allowlist.
func (v *URLValidator) AddAllowedDomain(domain string) {
	v.allowedDomains[strings.ToLower(strings.TrimSuffix(domain, "."))] = true
}

// AddBlockedDomain adds a domain to the blocklist.
func (v *URLValidator) AddBlockedDomain(domain string) {
	v.blockedDomains[strings.ToLower(strings.TrimSuffix(domain, "."))] = true
}

// IsSafe returns true if the URL is safe to access.
func (v *URLValidator) IsSafe(rawURL string) bool {
	result := v.Validate(rawURL)
	return result.Valid && result.Risk == URLRiskSafe
}

func (v *URLValidator) isLocalhost(host string) bool {
	host = strings.ToLower(host)
	if host == "localhost" || host == "127.0.0.1" || host == "::1" {
		return true
	}
	if strings.HasSuffix(host, ".localhost") {
		return true
	}
	// Check for 127.x.x.x range
	if ip := net.ParseIP(host); ip != nil {
		return v.isLoopback(ip)
	}
	return false
}

func (v *URLValidator) isLoopback(ip net.IP) bool {
	return ip.IsLoopback() || ip.IsUnspecified()
}

func (v *URLValidator) isMetadataService(host string) bool {
	for _, metaIP := range v.metadataIPs {
		if ip := net.ParseIP(host); ip != nil && ip.Equal(metaIP) {
			return true
		}
	}

	// Check hostname patterns
	metadataHosts := []string{
		"metadata.google.internal",
		"metadata.google.com",
		"metadata",
	}
	host = strings.ToLower(host)
	for _, mh := range metadataHosts {
		if host == mh {
			return true
		}
	}

	return false
}

func (v *URLValidator) isPrivateIP(ip net.IP) bool {
	if ip.IsUnspecified() {
		return true
	}
	for _, cidr := range v.privateRanges {
		if cidr.Contains(ip) {
			return true
		}
	}
	return false
}

func (v *URLValidator) isBlockedDomain(host string) bool {
	host = strings.ToLower(host)

	// Direct match
	if v.blockedDomains[host] {
		return true
	}

	// Check subdomains
	for blocked := range v.blockedDomains {
		if strings.HasSuffix(host, "."+blocked) {
			return true
		}
	}

	return false
}

func (v *URLValidator) isAllowedDomain(host string) bool {
	host = strings.ToLower(host)

	// Direct match
	if v.allowedDomains[host] {
		return true
	}

	// Check parent domains
	for allowed := range v.allowedDomains {
		if strings.HasSuffix(host, "."+allowed) {
			return true
		}
	}

	return false
}

func (v *URLValidator) isExfilService(host string) bool {
	host = strings.ToLower(host)
	for _, pattern := range v.exfilPatterns {
		if pattern.MatchString(host) {
			return true
		}
	}
	return false
}

func (v *URLValidator) isIPAddress(host string) bool {
	return net.ParseIP(host) != nil
}

// ExportPatterns returns all URL exfiltration patterns as ExportedPatterns for Firestore seeding.
func (v *URLValidator) ExportPatterns() []ExportedPattern {
	out := make([]ExportedPattern, 0, len(v.exfilPatterns))
	// Pattern names mirror the exfil service domains
	names := []string{
		"pastebin", "hastebin", "ghostbin", "transfer_sh", "file_io",
		"temp_sh", "0x0_st", "ix_io", "sprunge_us", "dpaste",
		"termbin", "webhook_site", "requestbin", "ngrok", "localhost_run",
	}
	for i, p := range v.exfilPatterns {
		name := "url_exfil_unknown"
		if i < len(names) {
			name = "url_exfil_" + names[i]
		}
		out = append(out, ExportedPattern{
			Name:       name,
			Pattern:    p.String(),
			Category:   "exfiltration",
			Domain:     "url_exfiltration",
			Severity:   0.7,
			Confidence: 0.9,
		})
	}
	return out
}

func (v *URLValidator) loadPrivateRanges() {
	// RFC 1918 private ranges
	privateRangeStrs := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"127.0.0.0/8",        // Loopback
		"169.254.0.0/16",     // Link-local
		"0.0.0.0/8",          // "This" network
		"224.0.0.0/4",        // Multicast
		"255.255.255.255/32", // Broadcast
		"fc00::/7",           // IPv6 unique local
		"fe80::/10",          // IPv6 link-local
		"::1/128",            // IPv6 loopback
	}

	for _, cidr := range privateRangeStrs {
		_, ipnet, err := net.ParseCIDR(cidr)
		if err == nil {
			v.privateRanges = append(v.privateRanges, ipnet)
		}
	}
}

func (v *URLValidator) loadMetadataIPs() {
	// Cloud metadata service IPs
	metadataIPStrs := []string{
		"169.254.169.254", // AWS, Azure, GCP
		"169.254.170.2",   // AWS ECS
		"fd00:ec2::254",   // AWS IPv6
	}

	for _, ipStr := range metadataIPStrs {
		if ip := net.ParseIP(ipStr); ip != nil {
			v.metadataIPs = append(v.metadataIPs, ip)
		}
	}
}

func (v *URLValidator) loadBlockedDomains() {
	// Known malicious domains from ClawHavoc and threat intel
	blockedDomains := []string{
		"fake-update.com",
		"skill-update.xyz",
		"clawhub-mirror.com",
		"clawhub-mirror.io",
	}

	for _, domain := range blockedDomains {
		v.blockedDomains[domain] = true
	}
}

func (v *URLValidator) loadExfilPatterns() {
	// Common exfiltration services
	exfilPatterns := []string{
		`(?i)pastebin\.com`,
		`(?i)hastebin\.com`,
		`(?i)ghostbin\.(co|com)`,
		`(?i)transfer\.sh`,
		`(?i)file\.io`,
		`(?i)temp\.sh`,
		`(?i)0x0\.st`,
		`(?i)ix\.io`,
		`(?i)sprunge\.us`,
		`(?i)dpaste\.`,
		`(?i)termbin\.com`,
		`(?i)webhook\.site`,
		`(?i)requestbin\.`,
		`(?i)ngrok\.io`,
		`(?i)localhost\.run`,
	}

	for _, pattern := range exfilPatterns {
		if re, err := regexp.Compile(pattern); err == nil {
			v.exfilPatterns = append(v.exfilPatterns, re)
		}
	}
}
