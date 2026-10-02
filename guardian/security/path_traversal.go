// Copyright 2025-2026 TakeInterest Inc.
// SPDX-License-Identifier: Apache-2.0

// Package security provides path traversal detection for AI agents
// with filesystem access.
package security

import (
	"regexp"
	"strings"
)

// PathTraversalCategory categorizes path traversal attack types.
type PathTraversalCategory string

const (
	PathCategoryBasicTraversal   PathTraversalCategory = "basic_traversal"
	PathCategoryEncodedTraversal PathTraversalCategory = "encoded_traversal"
	PathCategoryNullByte         PathTraversalCategory = "null_byte"
	PathCategoryWindowsSpecific  PathTraversalCategory = "windows_specific"
	PathCategoryUNCPath          PathTraversalCategory = "unc_path"
	PathCategorySensitivePath    PathTraversalCategory = "sensitive_path"
	PathCategorySymlinkEscape    PathTraversalCategory = "symlink_escape"
	PathCategoryArchiveSlip      PathTraversalCategory = "archive_slip"
	PathCategoryVirtualFS        PathTraversalCategory = "virtual_filesystem"
	PathCategoryEncodingNorm     PathTraversalCategory = "encoding_normalization"
	PathCategoryOSSpecificPath   PathTraversalCategory = "os_specific_path"
)

// PathTraversalPattern represents a path traversal detection pattern.
type PathTraversalPattern struct {
	Pattern    *regexp.Regexp
	Category   PathTraversalCategory
	Severity   float64 // 0.0-1.0
	Confidence float64 // 0.0-1.0
	Name       string
	Example    string
}

// PathTraversalPatterns contains comprehensive path traversal detection.
// Total: 35 patterns across 7 categories.
var PathTraversalPatterns = []PathTraversalPattern{
	// === Basic Traversal (5 patterns) ===
	{regexp.MustCompile(`(?:^|[/\\])\.\.(?:[/\\]|$)`), PathCategoryBasicTraversal, 0.90, 0.85, "dotdot_slash", `../../etc/passwd`},
	{regexp.MustCompile(`(?:^|/)\.\.\.+(?:/|$)`), PathCategoryBasicTraversal, 0.85, 0.80, "triple_dot_traversal", `.../etc/passwd`},
	{regexp.MustCompile(`\.\.[/\\]\.\.[/\\]`), PathCategoryBasicTraversal, 0.95, 0.90, "double_traversal", `../../../../../../etc/passwd`},
	{regexp.MustCompile(`\.\.;/`), PathCategoryBasicTraversal, 0.90, 0.85, "semicolon_traversal", `..;/..;/etc/passwd`},
	{regexp.MustCompile(`\.\.[\x00-\x1f]/`), PathCategoryBasicTraversal, 0.95, 0.90, "control_char_traversal", "..\x01/etc/passwd"},

	// === Encoded Traversal (8 patterns) ===
	{regexp.MustCompile(`(?i)%2e%2e[/\\%]`), PathCategoryEncodedTraversal, 0.95, 0.90, "url_encoded_dotdot", `%2e%2e/etc/passwd`},
	{regexp.MustCompile(`(?i)%2e%2e%2f`), PathCategoryEncodedTraversal, 0.95, 0.90, "full_url_encoded", `%2e%2e%2f%2e%2e%2f`},
	{regexp.MustCompile(`(?i)%252e%252e`), PathCategoryEncodedTraversal, 0.95, 0.95, "double_url_encoded", `%252e%252e%252fetc`},
	{regexp.MustCompile(`(?i)\.%2e/`), PathCategoryEncodedTraversal, 0.90, 0.85, "partial_encoded_dot", `.%2e/etc/passwd`},
	{regexp.MustCompile(`(?i)%2e\./`), PathCategoryEncodedTraversal, 0.90, 0.85, "partial_encoded_dot2", `%2e./etc/passwd`},
	{regexp.MustCompile(`(?i)%c0%ae`), PathCategoryEncodedTraversal, 0.95, 0.90, "overlong_utf8_dot", `%c0%ae%c0%ae/etc/passwd`},
	{regexp.MustCompile(`(?i)%c1%1c`), PathCategoryEncodedTraversal, 0.95, 0.90, "overlong_utf8_slash", `..%c1%1cetc%c1%1cpasswd`},
	{regexp.MustCompile(`(?i)%uff0e%uff0e`), PathCategoryEncodedTraversal, 0.90, 0.85, "fullwidth_dots", `%uff0e%uff0e/etc/passwd`},

	// === Null Byte (3 patterns) ===
	{regexp.MustCompile(`%00`), PathCategoryNullByte, 0.95, 0.90, "null_byte_url_encoded", `../../etc/passwd%00.jpg`},
	{regexp.MustCompile(`\x00`), PathCategoryNullByte, 0.95, 0.95, "null_byte_raw", "../../etc/passwd\x00.jpg"},
	{regexp.MustCompile(`(?i)%0d%0a`), PathCategoryNullByte, 0.85, 0.80, "crlf_in_path", `file.txt%0d%0a../../etc/passwd`},

	// === Windows-Specific (5 patterns) ===
	{regexp.MustCompile(`(?i)\.\.\\`), PathCategoryWindowsSpecific, 0.90, 0.85, "backslash_traversal", `..\..\windows\system32`},
	{regexp.MustCompile(`(?i)[a-z]:\\`), PathCategoryWindowsSpecific, 0.80, 0.75, "drive_letter_path", `C:\windows\system32\config\sam`},
	{regexp.MustCompile(`(?i)\\\\[^\\]+\\`), PathCategoryWindowsSpecific, 0.85, 0.80, "unc_prefix", `\\server\share\file`},
	{regexp.MustCompile(`(?i)(?:con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\.\w+)?$`), PathCategoryWindowsSpecific, 0.80, 0.75, "windows_device_name", `CON`},
	{regexp.MustCompile(`::?\$DATA`), PathCategoryWindowsSpecific, 0.90, 0.85, "ntfs_alternate_stream", `file.txt::$DATA`},

	// === Sensitive Path Access (9 patterns) ===
	{regexp.MustCompile(`(?i)(?:^|[/\\])etc[/\\](?:passwd|shadow|hosts|sudoers)`), PathCategorySensitivePath, 0.95, 0.95, "unix_credentials", `/etc/passwd`},
	{regexp.MustCompile(`(?i)(?:^|[/\\])\.(?:ssh|gnupg|aws|kube|docker)[/\\]`), PathCategorySensitivePath, 0.95, 0.95, "dotfile_secrets", `~/.ssh/id_rsa`},
	{regexp.MustCompile(`(?i)(?:^|[/\\])\.(?:env|netrc|npmrc|pypirc|gem/credentials)`), PathCategorySensitivePath, 0.95, 0.90, "credential_files", `.env`},
	{regexp.MustCompile(`(?i)(?:^|[/\\])\.git[/\\](?:config|HEAD|index|objects)`), PathCategorySensitivePath, 0.90, 0.85, "git_internals", `.git/config`},
	{regexp.MustCompile(`(?i)(?:^|[/\\])proc[/\\](?:self|[0-9]+)[/\\](?:environ|mem|maps|cmdline|root\b|fd[/\\]|cwd\b)`), PathCategorySensitivePath, 0.90, 0.90, "proc_filesystem", `/proc/self/environ`},
	{regexp.MustCompile(`(?i)(?:^|[/\\])(?:id_rsa|id_ed25519|id_ecdsa)(?:\.pub)?$`), PathCategorySensitivePath, 0.95, 0.90, "ssh_key_access", `id_rsa`},
	{regexp.MustCompile(`(?i)(?:^|[/\\])(?:credentials|secrets?)\.(?:json|ya?ml|toml|ini|cfg)$`), PathCategorySensitivePath, 0.90, 0.85, "config_secrets", `credentials.json`},
	{regexp.MustCompile(`(?i)(?:^|[/\\])\.(?:bash_history|zsh_history|mysql_history|psql_history)`), PathCategorySensitivePath, 0.85, 0.80, "shell_history", `.bash_history`},
	{regexp.MustCompile(`(?i)(?:^|[/\\])(?:web|app)\.config$`), PathCategorySensitivePath, 0.85, 0.80, "webapp_config", `web.config`},

	// === Symlink Escape (5 patterns) ===
	{regexp.MustCompile(`(?i)/dev/(?:fd|stdin|stdout|stderr)/`), PathCategorySymlinkEscape, 0.90, 0.85, "dev_fd_escape", `/dev/fd/3/../../../etc/passwd`},
	{regexp.MustCompile(`(?i)/proc/self/(?:root|cwd|fd)/`), PathCategorySymlinkEscape, 0.90, 0.90, "proc_self_escape", `/proc/self/root/etc/passwd`},
	{regexp.MustCompile(`(?i)/proc/self/environ`), PathCategorySymlinkEscape, 0.95, 0.90, "proc_environ_read", `/proc/self/environ`},
	{regexp.MustCompile(`(?i)(?:readlink|realpath|ln\s+-s)`), PathCategorySymlinkEscape, 0.75, 0.70, "symlink_commands", `ln -s /etc/passwd /tmp/link`},
	{regexp.MustCompile(`(?i)/run/secrets/`), PathCategorySymlinkEscape, 0.90, 0.85, "container_secrets", `/run/secrets/db-password`},

	// === Archive/Zip Slip (10 patterns) ===
	{regexp.MustCompile(`(?i)Content-Disposition.*filename.*\.\./`), PathCategoryArchiveSlip, 0.95, 0.90, "content_disp_traversal", `Content-Disposition: attachment; filename="../../evil.sh"`},
	{regexp.MustCompile(`(?i)\.jar!\.\./`), PathCategoryArchiveSlip, 0.95, 0.90, "jar_slip", `file.jar!../../etc/passwd`},
	{regexp.MustCompile(`(?i)\.war!\.\./`), PathCategoryArchiveSlip, 0.95, 0.90, "war_slip", `webapp.war!../../WEB-INF/web.xml`},
	{regexp.MustCompile(`(?i)\.zip!\.\./`), PathCategoryArchiveSlip, 0.95, 0.90, "zip_slip", `archive.zip!../../etc/passwd`},
	{regexp.MustCompile(`(?i)(?:unzip|tar\s+[xz])\s+.*\.\./`), PathCategoryArchiveSlip, 0.90, 0.85, "extract_traversal", `unzip -o archive.zip ../../evil`},
	{regexp.MustCompile(`(?i)tar\s+.*--absolute-names`), PathCategoryArchiveSlip, 0.85, 0.80, "tar_absolute_names", `tar --absolute-names -xf archive.tar`},
	{regexp.MustCompile(`(?i)META-INF/\.\./`), PathCategoryArchiveSlip, 0.90, 0.85, "meta_inf_traversal", `META-INF/../../etc/passwd`},
	{regexp.MustCompile(`(?i)WEB-INF/\.\./`), PathCategoryArchiveSlip, 0.90, 0.85, "web_inf_traversal", `WEB-INF/../../etc/passwd`},
	{regexp.MustCompile(`(?i)multipart.*filename.*\.\./`), PathCategoryArchiveSlip, 0.90, 0.85, "multipart_traversal", `multipart filename="../../evil"`},
	{regexp.MustCompile(`(?i)\.tar\.gz!\.\./`), PathCategoryArchiveSlip, 0.90, 0.85, "tar_gz_slip", `archive.tar.gz!../../etc/passwd`},

	// === Virtual Filesystem (10 patterns) ===
	{regexp.MustCompile(`(?i)/dev/shm/`), PathCategoryVirtualFS, 0.85, 0.80, "dev_shm", `/dev/shm/malware`},
	{regexp.MustCompile(`(?i)/sys/kernel/`), PathCategoryVirtualFS, 0.90, 0.85, "sys_kernel", `/sys/kernel/`},
	{regexp.MustCompile(`(?i)/sys/firmware/`), PathCategoryVirtualFS, 0.90, 0.85, "sys_firmware", `/sys/firmware/acpi/tables`},
	{regexp.MustCompile(`(?i)/sys/class/`), PathCategoryVirtualFS, 0.80, 0.75, "sys_class", `/sys/class/net/`},
	{regexp.MustCompile(`(?i)/proc/\d+/(?:mem|maps|environ|cmdline|status)\b`), PathCategoryVirtualFS, 0.95, 0.90, "proc_pid_sensitive", `/proc/1/environ`},
	{regexp.MustCompile(`(?i)/proc/self/(?:maps|mem|environ|cmdline)\b`), PathCategoryVirtualFS, 0.95, 0.90, "proc_self_sensitive", `/proc/self/maps`},
	{regexp.MustCompile(`(?i)/proc/self/map_files/`), PathCategoryVirtualFS, 0.90, 0.85, "proc_self_map_files", `/proc/self/map_files/`},
	{regexp.MustCompile(`(?i)/proc/kcore\b`), PathCategoryVirtualFS, 1.0, 0.95, "proc_kcore", `/proc/kcore`},
	{regexp.MustCompile(`(?i)/proc/kallsyms\b`), PathCategoryVirtualFS, 0.95, 0.90, "proc_kallsyms", `/proc/kallsyms`},
	{regexp.MustCompile(`(?i)/var/run/secrets/`), PathCategoryVirtualFS, 0.90, 0.85, "var_run_secrets", `/var/run/secrets/`},

	// === Encoding Normalization (10 patterns) ===
	{regexp.MustCompile(`(?i)%ef%bc%8f`), PathCategoryEncodingNorm, 0.90, 0.85, "fullwidth_slash", `%ef%bc%8f`},
	{regexp.MustCompile(`(?i)%ef%bc%bc`), PathCategoryEncodingNorm, 0.90, 0.85, "fullwidth_backslash", `%ef%bc%bc`},
	{regexp.MustCompile(`(?i)%e2%80%ae`), PathCategoryEncodingNorm, 0.90, 0.85, "rtl_override", `%e2%80%ae`},
	{regexp.MustCompile(`(?i)%e2%80%8b`), PathCategoryEncodingNorm, 0.85, 0.80, "zws_in_path", `%e2%80%8b`},
	{regexp.MustCompile(`(?i)\\xc0\\xaf`), PathCategoryEncodingNorm, 0.95, 0.90, "overlong_slash_raw", `\xc0\xaf`},
	{regexp.MustCompile(`(?i)\\xc1\\x9c`), PathCategoryEncodingNorm, 0.95, 0.90, "overlong_backslash_raw", `\xc1\x9c`},
	{regexp.MustCompile(`(?i)%u002e%u002e`), PathCategoryEncodingNorm, 0.95, 0.90, "iis_unicode_dots", `%u002e%u002e`},
	{regexp.MustCompile(`(?i)\.\.[%\\]c0[%\\]af`), PathCategoryEncodingNorm, 0.95, 0.90, "mixed_encoding_traversal", `..%c0%af`},
	{regexp.MustCompile(`(?i)%ef%bb%bf`), PathCategoryEncodingNorm, 0.80, 0.75, "bom_in_path", `%ef%bb%bf`},
	{regexp.MustCompile(`(?i)%e2%81%a0`), PathCategoryEncodingNorm, 0.80, 0.75, "word_joiner_in_path", `%e2%81%a0`},

	// === OS-Specific Sensitive Paths (10 patterns) ===
	{regexp.MustCompile(`(?i)(?:^|[/\\])etc[/\\](?:group|gshadow|login\.defs)\b`), PathCategoryOSSpecificPath, 0.90, 0.85, "etc_group_files", `/etc/group`},
	{regexp.MustCompile(`(?i)(?:^|[/\\])etc[/\\](?:crontab|anacrontab)\b`), PathCategoryOSSpecificPath, 0.85, 0.80, "etc_cron_files", `/etc/crontab`},
	{regexp.MustCompile(`(?i)(?:^|[/\\])etc[/\\](?:resolv\.conf|nsswitch\.conf)\b`), PathCategoryOSSpecificPath, 0.80, 0.75, "etc_dns_files", `/etc/resolv.conf`},
	{regexp.MustCompile(`(?i)(?:^|[/\\])etc[/\\](?:fstab|mtab)\b`), PathCategoryOSSpecificPath, 0.85, 0.80, "etc_mount_files", `/etc/fstab`},
	{regexp.MustCompile(`(?i)(?:^|[/\\])boot[/\\](?:vmlinuz|grub)\b`), PathCategoryOSSpecificPath, 0.90, 0.85, "boot_files", `/boot/vmlinuz`},
	{regexp.MustCompile(`(?i)(?:^|[/\\])root[/\\]\.(?:bashrc|ssh)\b`), PathCategoryOSSpecificPath, 0.95, 0.90, "root_dotfiles", `/root/.bashrc`},
	{regexp.MustCompile(`(?i)(?:^|[/\\])wp-config\.php\b`), PathCategoryOSSpecificPath, 0.90, 0.85, "wp_config", `wp-config.php`},
	{regexp.MustCompile(`(?i)(?:^|[/\\])\.ht(?:access|passwd)\b`), PathCategoryOSSpecificPath, 0.90, 0.85, "htaccess_htpasswd", `.htaccess`},
	{regexp.MustCompile(`(?i)(?:^|[/\\])(?:web\.xml|application\.properties)\b`), PathCategoryOSSpecificPath, 0.85, 0.80, "java_webapp_config", `web.xml`},
	{regexp.MustCompile(`(?i)(?:^|[/\\])appsettings(?:\..*)?\.json\b`), PathCategoryOSSpecificPath, 0.85, 0.80, "dotnet_appsettings", `appsettings.json`},
}

// CheckPathTraversal checks input for path traversal patterns and returns all findings.
func CheckPathTraversal(input string) []PathTraversalFinding {
	if len(input) == 0 {
		return nil
	}

	var findings []PathTraversalFinding

	// Quick pre-filter
	if !strings.ContainsAny(input, "./\\%") {
		return nil
	}

	for i := range PathTraversalPatterns {
		p := &PathTraversalPatterns[i]
		if p.Pattern.MatchString(input) {
			findings = append(findings, PathTraversalFinding{
				Pattern:    p,
				MatchedStr: p.Pattern.FindString(input),
			})
		}
	}
	return findings
}

// PathTraversalFinding represents a matched path traversal pattern.
type PathTraversalFinding struct {
	Pattern    *PathTraversalPattern
	MatchedStr string
}
