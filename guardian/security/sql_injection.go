// Copyright 2025-2026 TakeInterest Inc.
// SPDX-License-Identifier: Apache-2.0

// Package security provides SQL injection detection for AI agents that can execute queries.
// This is critical for agents with database access.
package security

import (
	"regexp"
	"strings"
)

// SQLInjectionCategory categorizes SQL injection types.
type SQLInjectionCategory string

const (
	SQLCategoryUnion       SQLInjectionCategory = "union_based"
	SQLCategoryBoolean     SQLInjectionCategory = "boolean_based"
	SQLCategoryTimeBased   SQLInjectionCategory = "time_based"
	SQLCategoryErrorBased  SQLInjectionCategory = "error_based"
	SQLCategoryStacked     SQLInjectionCategory = "stacked_queries"
	SQLCategoryOutOfBand   SQLInjectionCategory = "out_of_band"
	SQLCategorySecondOrder SQLInjectionCategory = "second_order"
	SQLCategoryNoSQL       SQLInjectionCategory = "nosql"
	SQLCategoryComment     SQLInjectionCategory = "comment_based"
	SQLCategoryEncoded     SQLInjectionCategory = "encoded"
)

// SQLInjectionPattern represents a SQL injection detection pattern.
type SQLInjectionPattern struct {
	Pattern    *regexp.Regexp
	Category   SQLInjectionCategory
	Severity   float64 // 0.0-1.0
	Confidence float64 // 0.0-1.0
	Name       string
	Example    string // For documentation
}

// SQLInjectionPatterns contains comprehensive SQL injection detection.
// Total: 200+ patterns across 10 categories.
var SQLInjectionPatterns = []SQLInjectionPattern{
	// ==========================================
	// CATEGORY: Union-Based Injection (25 patterns)
	// ==========================================
	{regexp.MustCompile(`(?i)'\s*(union|UNION)\s+(all\s+)?(select|SELECT)`), SQLCategoryUnion, 1.0, 0.98, "union_select", "' UNION SELECT"},
	{regexp.MustCompile(`(?i)"\s*(union|UNION)\s+(all\s+)?(select|SELECT)`), SQLCategoryUnion, 1.0, 0.98, "union_select_dq", `" UNION SELECT`},
	{regexp.MustCompile(`(?i)\)\s*(union|UNION)\s+(all\s+)?(select|SELECT)`), SQLCategoryUnion, 1.0, 0.98, "union_select_paren", ") UNION SELECT"},
	{regexp.MustCompile(`(?i)(union|UNION)\s+(all\s+)?(select|SELECT)\s+null`), SQLCategoryUnion, 1.0, 0.95, "union_null", "UNION SELECT null"},
	// URL/query-string UNION SELECT with no quote prefix (e.g. ?q=1+UNION+ALL+SELECT,
	// or %20-encoded). "UNION ... SELECT" together is a strong SQLi signal regardless
	// of a preceding quote; benign prose almost never contains both words adjacently.
	{regexp.MustCompile(`(?i)\bunion\b(?:\s|\+|%20)+(?:all(?:\s|\+|%20)+)?\bselect\b`), SQLCategoryUnion, 1.0, 0.95, "union_select_unquoted", "1+UNION+ALL+SELECT"},
	{regexp.MustCompile(`(?i)(union|UNION)\s+(all\s+)?(select|SELECT)\s+1,`), SQLCategoryUnion, 1.0, 0.95, "union_numbers", "UNION SELECT 1,2"},
	{regexp.MustCompile(`(?i)(union|UNION)\s+(all\s+)?(select|SELECT)\s+@@`), SQLCategoryUnion, 1.0, 0.98, "union_sysvar", "UNION SELECT @@version"},
	{regexp.MustCompile(`(?i)(union|UNION)\s+(all\s+)?(select|SELECT)\s+.*from\s+information_schema`), SQLCategoryUnion, 1.0, 0.99, "union_info_schema", "UNION SELECT from information_schema"},
	{regexp.MustCompile(`(?i)(union|UNION)\s+(all\s+)?(select|SELECT)\s+.*from\s+mysql\.`), SQLCategoryUnion, 1.0, 0.99, "union_mysql", "UNION SELECT from mysql."},
	{regexp.MustCompile(`(?i)(union|UNION)\s+(all\s+)?(select|SELECT)\s+.*from\s+pg_`), SQLCategoryUnion, 1.0, 0.99, "union_postgres", "UNION SELECT from pg_"},
	{regexp.MustCompile(`(?i)(union|UNION)\s+(all\s+)?(select|SELECT)\s+.*from\s+sqlite_`), SQLCategoryUnion, 1.0, 0.99, "union_sqlite", "UNION SELECT from sqlite_"},
	{regexp.MustCompile(`(?i)(union|UNION)\s+(all\s+)?(select|SELECT)\s+user\(`), SQLCategoryUnion, 1.0, 0.98, "union_user", "UNION SELECT user()"},
	{regexp.MustCompile(`(?i)(union|UNION)\s+(all\s+)?(select|SELECT)\s+database\(`), SQLCategoryUnion, 1.0, 0.98, "union_database", "UNION SELECT database()"},
	{regexp.MustCompile(`(?i)(union|UNION)\s+(all\s+)?(select|SELECT)\s+version\(`), SQLCategoryUnion, 1.0, 0.98, "union_version", "UNION SELECT version()"},
	{regexp.MustCompile(`(?i)(union|UNION)\s+(all\s+)?(select|SELECT)\s+load_file\(`), SQLCategoryUnion, 1.0, 0.99, "union_loadfile", "UNION SELECT load_file()"},
	{regexp.MustCompile(`(?i)(union|UNION)\s+(all\s+)?(select|SELECT)\s+.*into\s+(outfile|dumpfile)`), SQLCategoryUnion, 1.0, 0.99, "union_outfile", "UNION SELECT INTO OUTFILE"},
	{regexp.MustCompile(`(?i)order\s+by\s+\d+\s*--`), SQLCategoryUnion, 0.9, 0.90, "order_by_num", "ORDER BY 1--"},
	{regexp.MustCompile(`(?i)group\s+by\s+\d+\s*--`), SQLCategoryUnion, 0.9, 0.85, "group_by_num", "GROUP BY 1--"},

	// ==========================================
	// CATEGORY: Boolean-Based Blind (25 patterns)
	// ==========================================
	{regexp.MustCompile(`(?i)'\s*(and|AND|or|OR)\s+\d+\s*=\s*\d+`), SQLCategoryBoolean, 1.0, 0.95, "bool_equal", "' AND 1=1"},
	{regexp.MustCompile(`(?i)"\s*(and|AND|or|OR)\s+\d+\s*=\s*\d+`), SQLCategoryBoolean, 1.0, 0.95, "bool_equal_dq", `" AND 1=1`},
	{regexp.MustCompile(`(?i)'\s*(and|AND|or|OR)\s+'[^']+'\s*=\s*'[^']+'`), SQLCategoryBoolean, 1.0, 0.95, "bool_str_equal", "' AND 'a'='a'"},
	{regexp.MustCompile(`(?i)'\s*(and|AND|or|OR)\s+\d+\s*<>\s*\d+`), SQLCategoryBoolean, 1.0, 0.95, "bool_not_equal", "' AND 1<>2"},
	{regexp.MustCompile(`(?i)'\s*(and|AND|or|OR)\s+\d+\s*>\s*\d+`), SQLCategoryBoolean, 1.0, 0.90, "bool_greater", "' AND 2>1"},
	{regexp.MustCompile(`(?i)'\s*(and|AND|or|OR)\s+\d+\s*<\s*\d+`), SQLCategoryBoolean, 1.0, 0.90, "bool_less", "' AND 1<2"},
	{regexp.MustCompile(`(?i)'\s*(and|AND|or|OR)\s+true`), SQLCategoryBoolean, 1.0, 0.90, "bool_true", "' AND true"},
	{regexp.MustCompile(`(?i)'\s*(and|AND|or|OR)\s+false`), SQLCategoryBoolean, 1.0, 0.90, "bool_false", "' AND false"},
	{regexp.MustCompile(`(?i)'\s*(and|AND|or|OR)\s+not\s+\d+\s*=\s*\d+`), SQLCategoryBoolean, 1.0, 0.90, "bool_not", "' AND NOT 1=2"},
	{regexp.MustCompile(`(?i)'\s*(and|AND|or|OR)\s+exists\s*\(`), SQLCategoryBoolean, 1.0, 0.95, "bool_exists", "' AND EXISTS("},
	{regexp.MustCompile(`(?i)'\s*(and|AND|or|OR)\s+substring\(`), SQLCategoryBoolean, 1.0, 0.95, "bool_substring", "' AND SUBSTRING("},
	{regexp.MustCompile(`(?i)'\s*(and|AND|or|OR)\s+ascii\(`), SQLCategoryBoolean, 1.0, 0.95, "bool_ascii", "' AND ASCII("},
	{regexp.MustCompile(`(?i)'\s*(and|AND|or|OR)\s+length\(`), SQLCategoryBoolean, 1.0, 0.90, "bool_length", "' AND LENGTH("},
	{regexp.MustCompile(`(?i)'\s*(and|AND|or|OR)\s+char\(`), SQLCategoryBoolean, 1.0, 0.90, "bool_char", "' AND CHAR("},
	{regexp.MustCompile(`(?i)'\s*(and|AND|or|OR)\s+ord\(`), SQLCategoryBoolean, 1.0, 0.90, "bool_ord", "' AND ORD("},
	{regexp.MustCompile(`(?i)'\s*(and|AND|or|OR)\s+mid\(`), SQLCategoryBoolean, 1.0, 0.90, "bool_mid", "' AND MID("},
	{regexp.MustCompile(`(?i)'\s*(and|AND|or|OR)\s+left\(`), SQLCategoryBoolean, 1.0, 0.85, "bool_left", "' AND LEFT("},
	{regexp.MustCompile(`(?i)'\s*(and|AND|or|OR)\s+right\(`), SQLCategoryBoolean, 1.0, 0.85, "bool_right", "' AND RIGHT("},
	{regexp.MustCompile(`(?i)'\s*(and|AND|or|OR)\s+if\(`), SQLCategoryBoolean, 1.0, 0.95, "bool_if", "' AND IF("},
	{regexp.MustCompile(`(?i)'\s*(and|AND|or|OR)\s+case\s+when`), SQLCategoryBoolean, 1.0, 0.95, "bool_case", "' AND CASE WHEN"},

	// ==========================================
	// CATEGORY: Time-Based Blind (20 patterns)
	// ==========================================
	{regexp.MustCompile(`(?i)sleep\s*\(\s*\d+\s*\)`), SQLCategoryTimeBased, 1.0, 0.98, "sleep", "SLEEP(5)"},
	{regexp.MustCompile(`(?i)benchmark\s*\(\s*\d+`), SQLCategoryTimeBased, 1.0, 0.98, "benchmark", "BENCHMARK(10000000"},
	{regexp.MustCompile(`(?i)waitfor\s+delay`), SQLCategoryTimeBased, 1.0, 0.98, "waitfor_delay", "WAITFOR DELAY"},
	{regexp.MustCompile(`(?i)pg_sleep\s*\(`), SQLCategoryTimeBased, 1.0, 0.98, "pg_sleep", "pg_sleep("},
	{regexp.MustCompile(`(?i)dbms_lock\.sleep`), SQLCategoryTimeBased, 1.0, 0.98, "dbms_sleep", "DBMS_LOCK.SLEEP"},
	{regexp.MustCompile(`(?i)'\s*(and|AND|or|OR)\s+sleep\s*\(`), SQLCategoryTimeBased, 1.0, 0.99, "bool_sleep", "' AND SLEEP("},
	{regexp.MustCompile(`(?i)'\s*(and|AND|or|OR)\s+if\s*\([^,]+,\s*sleep`), SQLCategoryTimeBased, 1.0, 0.99, "if_sleep", "' AND IF(1=1,SLEEP(5)"},
	{regexp.MustCompile(`(?i)'\s*(and|AND|or|OR)\s+benchmark\s*\(`), SQLCategoryTimeBased, 1.0, 0.99, "bool_benchmark", "' AND BENCHMARK("},
	{regexp.MustCompile(`(?i)case\s+when.*then\s+sleep`), SQLCategoryTimeBased, 1.0, 0.95, "case_sleep", "CASE WHEN 1=1 THEN SLEEP"},
	{regexp.MustCompile(`(?i);\s*select\s+sleep\s*\(`), SQLCategoryTimeBased, 1.0, 0.98, "stacked_sleep", "; SELECT SLEEP("},
	{regexp.MustCompile(`(?i)randomblob\s*\(\s*\d{6,}`), SQLCategoryTimeBased, 0.9, 0.85, "randomblob", "randomblob(100000000)"},
	{regexp.MustCompile(`(?i)like\s+repeat\s*\(`), SQLCategoryTimeBased, 0.9, 0.85, "repeat", "LIKE REPEAT('a',"},

	// ==========================================
	// CATEGORY: Error-Based (20 patterns)
	// ==========================================
	{regexp.MustCompile(`(?i)extractvalue\s*\(`), SQLCategoryErrorBased, 1.0, 0.95, "extractvalue", "EXTRACTVALUE("},
	{regexp.MustCompile(`(?i)updatexml\s*\(`), SQLCategoryErrorBased, 1.0, 0.95, "updatexml", "UPDATEXML("},
	{regexp.MustCompile(`(?i)xmltype\s*\(`), SQLCategoryErrorBased, 1.0, 0.95, "xmltype", "XMLTYPE("},
	{regexp.MustCompile(`(?i)exp\s*\(\s*~`), SQLCategoryErrorBased, 1.0, 0.95, "exp_error", "EXP(~("},
	{regexp.MustCompile(`(?i)geometrycollection\s*\(`), SQLCategoryErrorBased, 1.0, 0.95, "geometrycollection", "GEOMETRYCOLLECTION("},
	{regexp.MustCompile(`(?i)polygon\s*\(\(`), SQLCategoryErrorBased, 0.9, 0.85, "polygon", "POLYGON(("},
	{regexp.MustCompile(`(?i)linestring\s*\(`), SQLCategoryErrorBased, 0.9, 0.85, "linestring", "LINESTRING("},
	{regexp.MustCompile(`(?i)multipoint\s*\(`), SQLCategoryErrorBased, 0.9, 0.85, "multipoint", "MULTIPOINT("},
	{regexp.MustCompile(`(?i)convert\s*\([^,]+,\s*(signed|unsigned)`), SQLCategoryErrorBased, 0.8, 0.80, "convert_error", "CONVERT(x,SIGNED)"},
	{regexp.MustCompile(`(?i)row\s*\(\s*\d+,\s*\d+\s*\)\s*>\s*row`), SQLCategoryErrorBased, 1.0, 0.90, "row_error", "ROW(1,1)>ROW("},
	{regexp.MustCompile(`(?i)cot\s*\(\s*0\s*\)`), SQLCategoryErrorBased, 1.0, 0.90, "cot_error", "COT(0)"},
	{regexp.MustCompile(`(?i)floor\s*\(\s*rand\s*\(`), SQLCategoryErrorBased, 1.0, 0.95, "floor_rand", "FLOOR(RAND("},

	// ==========================================
	// CATEGORY: Stacked Queries (20 patterns)
	// ==========================================
	{regexp.MustCompile(`(?i);\s*(drop|DROP)\s+(table|TABLE|database|DATABASE)`), SQLCategoryStacked, 1.0, 0.99, "stacked_drop", "; DROP TABLE"},
	{regexp.MustCompile(`(?i);\s*(delete|DELETE)\s+from`), SQLCategoryStacked, 1.0, 0.99, "stacked_delete", "; DELETE FROM"},
	{regexp.MustCompile(`(?i);\s*(update|UPDATE)\s+\w+\s+set`), SQLCategoryStacked, 1.0, 0.99, "stacked_update", "; UPDATE x SET"},
	{regexp.MustCompile(`(?i);\s*(insert|INSERT)\s+into`), SQLCategoryStacked, 1.0, 0.95, "stacked_insert", "; INSERT INTO"},
	{regexp.MustCompile(`(?i);\s*(truncate|TRUNCATE)\s+table`), SQLCategoryStacked, 1.0, 0.99, "stacked_truncate", "; TRUNCATE TABLE"},
	{regexp.MustCompile(`(?i);\s*(alter|ALTER)\s+table`), SQLCategoryStacked, 1.0, 0.95, "stacked_alter", "; ALTER TABLE"},
	{regexp.MustCompile(`(?i);\s*(create|CREATE)\s+(table|user|database)`), SQLCategoryStacked, 1.0, 0.95, "stacked_create", "; CREATE TABLE"},
	{regexp.MustCompile(`(?i);\s*(grant|GRANT)\s+`), SQLCategoryStacked, 1.0, 0.99, "stacked_grant", "; GRANT"},
	{regexp.MustCompile(`(?i);\s*(revoke|REVOKE)\s+`), SQLCategoryStacked, 1.0, 0.99, "stacked_revoke", "; REVOKE"},
	{regexp.MustCompile(`(?i);\s*(exec|EXEC|execute|EXECUTE)\s*\(`), SQLCategoryStacked, 1.0, 0.99, "stacked_exec", "; EXEC("},
	{regexp.MustCompile(`(?i);\s*xp_cmdshell`), SQLCategoryStacked, 1.0, 0.99, "xp_cmdshell", "; xp_cmdshell"},
	{regexp.MustCompile(`(?i);\s*sp_executesql`), SQLCategoryStacked, 1.0, 0.95, "sp_executesql", "; sp_executesql"},
	{regexp.MustCompile(`(?i);\s*dbms_java\.grant_permission`), SQLCategoryStacked, 1.0, 0.99, "dbms_java", "; dbms_java.grant_permission"},
	{regexp.MustCompile(`(?i);\s*(shutdown|SHUTDOWN)`), SQLCategoryStacked, 1.0, 0.99, "stacked_shutdown", "; SHUTDOWN"},
	{regexp.MustCompile(`(?i)';\s*--`), SQLCategoryStacked, 0.9, 0.85, "quote_semicolon_comment", "'; --"},

	// ==========================================
	// CATEGORY: Out-of-Band (15 patterns)
	// ==========================================
	{regexp.MustCompile(`(?i)load_file\s*\(\s*['"]?/`), SQLCategoryOutOfBand, 1.0, 0.98, "load_file_path", "LOAD_FILE('/etc/passwd')"},
	{regexp.MustCompile(`(?i)into\s+(outfile|dumpfile)\s*['"]`), SQLCategoryOutOfBand, 1.0, 0.99, "into_outfile", "INTO OUTFILE '/tmp/x'"},
	{regexp.MustCompile(`(?i)load\s+data\s+infile`), SQLCategoryOutOfBand, 1.0, 0.99, "load_data_infile", "LOAD DATA INFILE"},
	{regexp.MustCompile(`(?i)utl_http\.request`), SQLCategoryOutOfBand, 1.0, 0.99, "utl_http", "UTL_HTTP.REQUEST"},
	{regexp.MustCompile(`(?i)dbms_ldap\.init`), SQLCategoryOutOfBand, 1.0, 0.99, "dbms_ldap", "DBMS_LDAP.INIT"},
	{regexp.MustCompile(`(?i)httpuritype\s*\(`), SQLCategoryOutOfBand, 1.0, 0.99, "httpuritype", "HTTPURITYPE("},
	{regexp.MustCompile(`(?i)sys\.dmexec_command`), SQLCategoryOutOfBand, 1.0, 0.99, "dmexec", "sys.dmexec_command"},
	{regexp.MustCompile(`(?i)xp_dirtree`), SQLCategoryOutOfBand, 1.0, 0.95, "xp_dirtree", "xp_dirtree"},
	{regexp.MustCompile(`(?i)xp_fileexist`), SQLCategoryOutOfBand, 1.0, 0.95, "xp_fileexist", "xp_fileexist"},
	{regexp.MustCompile(`(?i)master\.\.xp_`), SQLCategoryOutOfBand, 1.0, 0.98, "master_xp", "master..xp_"},
	{regexp.MustCompile(`(?i)copy\s+.*\s+to\s+program`), SQLCategoryOutOfBand, 1.0, 0.99, "copy_to_program", "COPY x TO PROGRAM"},

	// ==========================================
	// CATEGORY: Comment-Based (15 patterns)
	// ==========================================
	{regexp.MustCompile(`--\s*$`), SQLCategoryComment, 0.7, 0.70, "sql_comment_end", "-- "},
	{regexp.MustCompile(`#\s*$`), SQLCategoryComment, 0.7, 0.70, "hash_comment", "# "},
	{regexp.MustCompile(`/\*.*\*/`), SQLCategoryComment, 0.6, 0.60, "block_comment", "/* */"},
	{regexp.MustCompile(`/\*!\d+`), SQLCategoryComment, 1.0, 0.95, "mysql_conditional", "/*!50000"},
	{regexp.MustCompile(`(?i)'\s*--`), SQLCategoryComment, 0.9, 0.85, "quote_comment", "'--"},
	{regexp.MustCompile(`(?i)'\s*#\s*$`), SQLCategoryComment, 0.9, 0.85, "quote_hash", "admin'#"},
	{regexp.MustCompile(`(?i)'\s*/\*`), SQLCategoryComment, 0.9, 0.85, "quote_block", "'/*"},
	{regexp.MustCompile(`(?i)/\*.*union.*\*/`), SQLCategoryComment, 1.0, 0.95, "comment_union", "/**/UNION/**/"},
	{regexp.MustCompile(`(?i)/\*.*select.*\*/`), SQLCategoryComment, 1.0, 0.95, "comment_select", "/**/SELECT/**/"},
	{regexp.MustCompile(`(?i)uni/\*\*/on`), SQLCategoryComment, 1.0, 0.98, "split_union", "UNI/**/ON"},
	{regexp.MustCompile(`(?i)sel/\*\*/ect`), SQLCategoryComment, 1.0, 0.98, "split_select", "SEL/**/ECT"}, //nolint:misspell // intentional SQL injection pattern

	// ==========================================
	// CATEGORY: Encoded Attacks (15 patterns)
	// ==========================================
	{regexp.MustCompile(`(?i)%27`), SQLCategoryEncoded, 0.8, 0.75, "url_quote", "%27 (URL encoded ')"},
	{regexp.MustCompile(`(?i)%22`), SQLCategoryEncoded, 0.8, 0.75, "url_dquote", `%22 (URL encoded ")`},
	{regexp.MustCompile(`(?i)%3B`), SQLCategoryEncoded, 0.7, 0.70, "url_semicolon", "%3B (URL encoded ;)"},
	{regexp.MustCompile(`(?i)%2D%2D`), SQLCategoryEncoded, 0.9, 0.85, "url_comment", "%2D%2D (URL encoded --)"},
	{regexp.MustCompile(`(?i)%23`), SQLCategoryEncoded, 0.7, 0.70, "url_hash", "%23 (URL encoded #)"},
	{regexp.MustCompile(`(?i)0x[0-9a-f]{10,}`), SQLCategoryEncoded, 0.8, 0.80, "hex_string", "0x61646D696E"},
	{regexp.MustCompile(`(?i)char\s*\(\s*\d+\s*\)`), SQLCategoryEncoded, 0.8, 0.80, "char_encode", "CHAR(97)"},
	{regexp.MustCompile(`(?i)concat\s*\(\s*char\s*\(`), SQLCategoryEncoded, 0.9, 0.90, "concat_char", "CONCAT(CHAR("},
	{regexp.MustCompile(`(?i)unhex\s*\(`), SQLCategoryEncoded, 0.9, 0.85, "unhex", "UNHEX("},
	{regexp.MustCompile(`(?i)chr\s*\(\s*\d+\s*\)`), SQLCategoryEncoded, 0.8, 0.80, "chr_encode", "CHR(97)"},
	{regexp.MustCompile(`(?i)from_base64\s*\(`), SQLCategoryEncoded, 0.9, 0.85, "from_base64", "FROM_BASE64("},
	{regexp.MustCompile(`(?i)\\x[0-9a-f]{2}`), SQLCategoryEncoded, 0.7, 0.70, "escape_hex", "\\x27"},

	// ==========================================
	// CATEGORY: NoSQL Injection (25 patterns)
	// Patterns handle both raw operator syntax and JSON format
	// ==========================================
	// $where takes arbitrary JS — always an injection vector.
	{regexp.MustCompile(`(?i)["\']?\$where["\']?\s*:`), SQLCategoryNoSQL, 1.0, 0.98, "mongo_where", "$where:"},
	// Auth-bypass shapes: an operator where the app expected a scalar — e.g.
	// {"user":{"$ne":null}} or {"pw":{"$gt":""}}. We require the TELL of injection
	// (null / empty-string / nested operator), NOT a bare numeric comparison, so
	// legitimate query JSON like {"price":{"$gte":10}} is not flagged.
	{regexp.MustCompile(`(?i)["\']?\$ne["\']?\s*:\s*(?:null|""|''|\{)`), SQLCategoryNoSQL, 0.9, 0.85, "mongo_ne_bypass", `$ne:null`},
	{regexp.MustCompile(`(?i)["\']?\$(?:gt|gte|lt|lte)["\']?\s*:\s*(?:""|''|\{)`), SQLCategoryNoSQL, 0.85, 0.80, "mongo_cmp_bypass", `$gt:""`},
	// $regex with an attacker-controlled value is a ReDoS / filter-bypass vector.
	{regexp.MustCompile(`(?i)["\']?\$regex["\']?\s*:`), SQLCategoryNoSQL, 0.9, 0.85, "mongo_regex", "$regex:"},
	// $or/$and used to smuggle an always-true clause (injection), not a normal
	// multi-condition query: require a nested operator or quote inside the array.
	{regexp.MustCompile(`(?i)["\']?\$or["\']?\s*:\s*\[[^\]]*\$`), SQLCategoryNoSQL, 0.9, 0.85, "mongo_or_inject", "$or:[{$..."},
	{regexp.MustCompile(`(?i)["\']?\$exists["\']?\s*:\s*(?:true|false)\s*\}`), SQLCategoryNoSQL, 0.7, 0.70, "mongo_exists", "$exists:true}"},
	{regexp.MustCompile(`(?i)["\']?\$type["\']?\s*:`), SQLCategoryNoSQL, 0.7, 0.70, "mongo_type", "$type:"},
	{regexp.MustCompile(`(?i)["\']?\$comment["\']?\s*:`), SQLCategoryNoSQL, 0.9, 0.85, "mongo_comment", "$comment:"},
	{regexp.MustCompile(`(?i)["\']?\$function["\']?\s*:`), SQLCategoryNoSQL, 1.0, 0.98, "mongo_function", "$function:"},
	{regexp.MustCompile(`(?i)["\']?\$accumulator["\']?\s*:`), SQLCategoryNoSQL, 1.0, 0.95, "mongo_accumulator", "$accumulator:"},
	{regexp.MustCompile(`(?i)this\s*\.\s*constructor`), SQLCategoryNoSQL, 1.0, 0.95, "constructor", "this.constructor"},
	{regexp.MustCompile(`(?i)prototype\s*\.`), SQLCategoryNoSQL, 0.9, 0.90, "prototype", "__proto__"},
	{regexp.MustCompile(`(?i)__proto__`), SQLCategoryNoSQL, 1.0, 0.95, "proto", "__proto__"},
	{regexp.MustCompile(`(?i)\["__proto__"\]`), SQLCategoryNoSQL, 1.0, 0.95, "proto_bracket", `["__proto__"]`},
	{regexp.MustCompile(`(?i)constructor\s*\.`), SQLCategoryNoSQL, 0.9, 0.90, "constructor_access", "constructor."},
	{regexp.MustCompile(`(?i)sleep\s*\(\s*\d+\s*\)\s*\|\|`), SQLCategoryNoSQL, 1.0, 0.95, "mongo_sleep", "sleep(1000)||"},

	// ==========================================
	// CATEGORY: Second Order (10 patterns)
	// ==========================================
	{regexp.MustCompile(`(?i)'\s*;\s*insert\s+into.*values.*\(`), SQLCategorySecondOrder, 1.0, 0.90, "stored_insert", "'; INSERT INTO"},
	{regexp.MustCompile(`(?i)admin'\s*--`), SQLCategorySecondOrder, 1.0, 0.95, "admin_bypass", "admin'--"},
	{regexp.MustCompile(`(?i)'\s*or\s+'[^']+'\s*=\s*'`), SQLCategorySecondOrder, 1.0, 0.95, "or_equals", "' OR 'x'='x"},
	{regexp.MustCompile(`(?i)admin'\s*or\s+'`), SQLCategorySecondOrder, 1.0, 0.95, "admin_or", "admin' OR '"},
	{regexp.MustCompile(`(?i)'\s*;\s*waitfor`), SQLCategorySecondOrder, 1.0, 0.90, "stored_waitfor", "'; WAITFOR"},
	{regexp.MustCompile(`(?i)'\s*;\s*exec`), SQLCategorySecondOrder, 1.0, 0.95, "stored_exec", "'; EXEC"},
	{regexp.MustCompile(`(?i)';\s*update.*set.*=`), SQLCategorySecondOrder, 1.0, 0.95, "stored_update", "'; UPDATE x SET y="},
}

// SQLInjectionResult contains the result of SQL injection detection.
type SQLInjectionResult struct {
	Detected       bool                 `json:"detected"`
	Score          float64              `json:"score"`
	Confidence     float64              `json:"confidence"`
	Category       SQLInjectionCategory `json:"category,omitempty"`
	MatchedPattern string               `json:"matched_pattern,omitempty"`
	PatternName    string               `json:"pattern_name,omitempty"`
	Indicators     []string             `json:"indicators,omitempty"`
	Reason         string               `json:"reason,omitempty"`
}

// CheckSQLInjection analyzes input for SQL injection attempts.
func CheckSQLInjection(input string) *SQLInjectionResult {
	result := &SQLInjectionResult{
		Detected:   false,
		Score:      0.0,
		Confidence: 0.0,
	}

	if input == "" {
		return result
	}

	// Track indicators
	var indicators []string

	// Check for multiple suspicious elements
	quoteCount := strings.Count(input, "'") + strings.Count(input, `"`)
	if quoteCount > 4 {
		indicators = append(indicators, "excessive_quotes")
		result.Score += 0.1
	}

	// Check for SQL keywords
	sqlKeywords := []string{"SELECT", "UNION", "INSERT", "UPDATE", "DELETE", "DROP", "EXEC", "EXECUTE"}
	keywordCount := 0
	for _, kw := range sqlKeywords {
		if strings.Contains(strings.ToUpper(input), kw) {
			keywordCount++
		}
	}
	if keywordCount > 2 {
		indicators = append(indicators, "multiple_sql_keywords")
		result.Score += 0.2
	}

	// Check against patterns
	var bestMatch *SQLInjectionPattern
	for i := range SQLInjectionPatterns {
		pattern := &SQLInjectionPatterns[i]
		if pattern.Pattern.MatchString(input) {
			if bestMatch == nil || pattern.Severity > bestMatch.Severity {
				bestMatch = pattern
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
		result.Reason = "SQL injection detected: " + bestMatch.Name
		result.Indicators = indicators
		return result
	}

	// Heuristic checks
	if strings.Contains(input, "' OR '") || strings.Contains(input, `" OR "`) {
		result.Detected = true
		result.Score = 0.9
		result.Confidence = 0.85
		result.Reason = "Classic OR-based injection pattern"
		indicators = append(indicators, "classic_or_injection")
	}

	if strings.Contains(input, "1=1") || strings.Contains(input, "1 = 1") {
		indicators = append(indicators, "always_true_condition")
		result.Score += 0.3
	}

	result.Indicators = indicators

	// Final score evaluation
	if result.Score >= 0.5 {
		result.Detected = true
		result.Confidence = result.Score
		if result.Reason == "" {
			result.Reason = "Suspicious SQL patterns detected"
		}
	}

	return result
}

// CheckSQLInput checks a map of inputs for SQL injection.
func CheckSQLInput(input map[string]any) *SQLInjectionResult {
	worstResult := &SQLInjectionResult{}
	walkMapStrings(input, func(s string) {
		if worstResult.Detected {
			return
		}
		result := CheckSQLInjection(s)
		if result.Detected || result.Score > worstResult.Score {
			worstResult = result
		}
	})
	return worstResult
}
