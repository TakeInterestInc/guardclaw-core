// Copyright 2025-2026 TakeInterest Inc.
// SPDX-License-Identifier: Apache-2.0

// Package security provides blocked tool and skill detection for Guardian.
// This file contains patterns for known malicious, dangerous, or suspicious
// MCP servers, npm packages, and tool patterns that should be blocked by default.
package security

import (
	"regexp"
	"strings"
)

// BlockedToolCategory categorizes blocked tools.
type BlockedToolCategory string

const (
	CategoryMalicious    BlockedToolCategory = "malicious"         // Known malware
	CategoryDangerous    BlockedToolCategory = "dangerous"         // High-risk operations
	CategorySuspicious   BlockedToolCategory = "suspicious"        // Potentially harmful
	CategoryTyposquatted BlockedToolCategory = "typosquatted"      // Fake package names
	CategoryCryptojacker BlockedToolCategory = "cryptojacker"      // Mining malware
	CategoryExfiltration BlockedToolCategory = "data_exfiltration" // Data theft
	CategoryBackdoor     BlockedToolCategory = "backdoor"          // Remote access
	CategoryCredStealer  BlockedToolCategory = "credential_stealer"
	CategoryDestructive  BlockedToolCategory = "destructive" // System damage
)

// BlockedToolPattern represents a pattern for blocked tools.
type BlockedToolPattern struct {
	Pattern     *regexp.Regexp
	Category    BlockedToolCategory
	Severity    float64 // 0.0-1.0
	Name        string
	Description string
}

// BlockedToolResult contains the result of a blocked tool check.
type BlockedToolResult struct {
	Blocked     bool                `json:"blocked"`
	Score       float64             `json:"score"`
	Category    BlockedToolCategory `json:"category,omitempty"`
	PatternName string              `json:"pattern_name,omitempty"`
	Reason      string              `json:"reason,omitempty"`
}

// BlockedToolPatterns contains patterns for known malicious tools/skills.
// This is a comprehensive database of patterns that Guardian blocks by default.
// Total: 275 patterns across 9 categories (as of 2026-02-02).
var BlockedToolPatterns = []BlockedToolPattern{
	// ==========================================
	// CATEGORY: Typosquatted npm packages (117 patterns)
	// Common typosquatting targets for popular packages
	// ==========================================

	// React ecosystem typosquats (only match actual typosquats, not legitimate packages)
	{regexp.MustCompile(`(?i)^re@ct$`), CategoryTyposquatted, 1.0, "typo_react_at", "Typosquat of react (@)"},
	{regexp.MustCompile(`(?i)^reakt$`), CategoryTyposquatted, 1.0, "typo_reakt", "Typosquat of react (k)"},
	{regexp.MustCompile(`(?i)^re4ct$`), CategoryTyposquatted, 1.0, "typo_re4ct", "Typosquat of react (4)"},
	{regexp.MustCompile(`(?i)^r3act$`), CategoryTyposquatted, 1.0, "typo_r3act", "Typosquat of react (3)"},
	{regexp.MustCompile(`(?i)^reactt$`), CategoryTyposquatted, 1.0, "typo_reactt", "Typosquat of react (double t)"},
	{regexp.MustCompile(`(?i)^raect$`), CategoryTyposquatted, 1.0, "typo_raect", "Typosquat of react (swap)"},
	{regexp.MustCompile(`(?i)^r3@ct-dom$`), CategoryTyposquatted, 1.0, "typo_react_dom", "Typosquat of react-dom"},
	{regexp.MustCompile(`(?i)^react-d0m$`), CategoryTyposquatted, 1.0, "typo_react_d0m", "Typosquat of react-dom (0)"},
	{regexp.MustCompile(`(?i)^reactdom$`), CategoryTyposquatted, 1.0, "typo_reactdom", "Typosquat of react-dom (no hyphen)"},
	{regexp.MustCompile(`(?i)^react-router-d0m$`), CategoryTyposquatted, 1.0, "typo_react_router_d0m", "Typosquat of react-router-dom"},
	{regexp.MustCompile(`(?i)^react-r0uter$`), CategoryTyposquatted, 1.0, "typo_react_r0uter", "Typosquat of react-router"},
	{regexp.MustCompile(`(?i)^react-scrip7s$`), CategoryTyposquatted, 1.0, "typo_react_scripts", "Typosquat of react-scripts"},
	{regexp.MustCompile(`(?i)^react-reduxs$`), CategoryTyposquatted, 1.0, "typo_react_redux", "Typosquat of react-redux"},
	{regexp.MustCompile(`(?i)^r3dux$`), CategoryTyposquatted, 1.0, "typo_redux", "Typosquat of redux"},
	{regexp.MustCompile(`(?i)^next-js$`), CategoryTyposquatted, 1.0, "typo_nextjs", "Typosquat of next (added -js)"},
	{regexp.MustCompile(`(?i)^nextjs$`), CategoryTyposquatted, 1.0, "typo_nextjs2", "Typosquat of next (nextjs no hyphen)"},
	{regexp.MustCompile(`(?i)^nex7$`), CategoryTyposquatted, 1.0, "typo_next", "Typosquat of next (7)"},

	// Vue ecosystem typosquats
	{regexp.MustCompile(`(?i)^vu3$`), CategoryTyposquatted, 1.0, "typo_vue", "Typosquat of vue (3)"},
	{regexp.MustCompile(`(?i)^veu$`), CategoryTyposquatted, 1.0, "typo_veu", "Typosquat of vue (swap)"},
	{regexp.MustCompile(`(?i)^vue-r0uter$`), CategoryTyposquatted, 1.0, "typo_vue_router", "Typosquat of vue-router"},
	{regexp.MustCompile(`(?i)^vu3x$`), CategoryTyposquatted, 1.0, "typo_vuex", "Typosquat of vuex"},
	{regexp.MustCompile(`(?i)^nux7$`), CategoryTyposquatted, 1.0, "typo_nuxt", "Typosquat of nuxt"},
	{regexp.MustCompile(`(?i)^nuxtjs$`), CategoryTyposquatted, 1.0, "typo_nuxtjs", "Typosquat of nuxt (added js)"},

	// Angular typosquats
	{regexp.MustCompile(`(?i)^@angul@r/`), CategoryTyposquatted, 1.0, "typo_angular", "Typosquat of @angular"},
	{regexp.MustCompile(`(?i)^@4ngular/`), CategoryTyposquatted, 1.0, "typo_4ngular", "Typosquat of @angular"},
	{regexp.MustCompile(`(?i)^angular-cli$`), CategoryTyposquatted, 1.0, "typo_angular_cli", "Typosquat of @angular/cli"},
	{regexp.MustCompile(`(?i)^angularjs$`), CategoryTyposquatted, 0.8, "typo_angularjs", "Potential confusion with AngularJS"},
	{regexp.MustCompile(`(?i)^@angul@r-devkit/`), CategoryTyposquatted, 1.0, "typo_angular_devkit", "Typosquat of @angular-devkit"},

	// Lodash typosquats (only match actual typos, not lodash itself)
	{regexp.MustCompile(`(?i)^l0dash$`), CategoryTyposquatted, 1.0, "typo_l0dash", "Typosquat of lodash (0)"},
	{regexp.MustCompile(`(?i)^1odash$`), CategoryTyposquatted, 1.0, "typo_1odash", "Typosquat of lodash (1)"},
	{regexp.MustCompile(`(?i)^lodahs$`), CategoryTyposquatted, 1.0, "typo_lodahs", "Typosquat of lodash (swap)"},
	{regexp.MustCompile(`(?i)^lod@sh$`), CategoryTyposquatted, 1.0, "typo_lod@sh", "Typosquat of lodash (@)"},
	{regexp.MustCompile(`(?i)^lodashe?s$`), CategoryTyposquatted, 1.0, "typo_lodashes", "Typosquat of lodash (plural)"},
	{regexp.MustCompile(`(?i)^underscores$`), CategoryTyposquatted, 0.8, "typo_underscores", "Typosquat of underscore (plural)"},
	{regexp.MustCompile(`(?i)^_underscore$`), CategoryTyposquatted, 0.9, "typo_underscore_prefix", "Typosquat of underscore"},

	// Express typosquats
	{regexp.MustCompile(`(?i)^express-js$`), CategoryTyposquatted, 1.0, "typo_expressjs", "Typosquat of express (added -js)"},
	{regexp.MustCompile(`(?i)^expressjs$`), CategoryTyposquatted, 1.0, "typo_expressjs2", "Typosquat of express (added js)"},
	{regexp.MustCompile(`(?i)^3xpress$`), CategoryTyposquatted, 1.0, "typo_3xpress", "Typosquat of express (3)"},
	{regexp.MustCompile(`(?i)^expres$`), CategoryTyposquatted, 1.0, "typo_expres", "Typosquat of express (missing s)"},
	{regexp.MustCompile(`(?i)^expresss$`), CategoryTyposquatted, 1.0, "typo_expresss", "Typosquat of express (extra s)"}, //nolint:misspell // intentional typosquat pattern
	{regexp.MustCompile(`(?i)^express-sessions$`), CategoryTyposquatted, 1.0, "typo_express_session", "Typosquat of express-session (plural)"},
	{regexp.MustCompile(`(?i)^body-pars3r$`), CategoryTyposquatted, 1.0, "typo_body_parser", "Typosquat of body-parser"},
	{regexp.MustCompile(`(?i)^bodyparser$`), CategoryTyposquatted, 1.0, "typo_bodyparser", "Typosquat of body-parser (no hyphen)"},

	// Webpack typosquats
	{regexp.MustCompile(`(?i)^w3bpack$`), CategoryTyposquatted, 1.0, "typo_w3bpack", "Typosquat of webpack (3)"},
	{regexp.MustCompile(`(?i)^webpak$`), CategoryTyposquatted, 1.0, "typo_webpak", "Typosquat of webpack (missing c)"},
	{regexp.MustCompile(`(?i)^webpackk$`), CategoryTyposquatted, 1.0, "typo_webpackk", "Typosquat of webpack (double k)"},
	{regexp.MustCompile(`(?i)^webpack-cIi$`), CategoryTyposquatted, 1.0, "typo_webpack_cli", "Typosquat of webpack-cli"},
	{regexp.MustCompile(`(?i)^webpack-d3v-server$`), CategoryTyposquatted, 1.0, "typo_webpack_dev_server", "Typosquat of webpack-dev-server"},

	// Babel typosquats
	{regexp.MustCompile(`(?i)^@bab3l/`), CategoryTyposquatted, 1.0, "typo_babel", "Typosquat of @babel (3)"},
	{regexp.MustCompile(`(?i)^@babel-/`), CategoryTyposquatted, 1.0, "typo_babel_hyphen", "Typosquat of @babel (extra hyphen)"},
	{regexp.MustCompile(`(?i)^bab3l-core$`), CategoryTyposquatted, 1.0, "typo_babel_core", "Typosquat of babel-core"},
	{regexp.MustCompile(`(?i)^babelcore$`), CategoryTyposquatted, 1.0, "typo_babelcore", "Typosquat of babel-core (no hyphen)"},
	{regexp.MustCompile(`(?i)^bab3l-loader$`), CategoryTyposquatted, 1.0, "typo_babel_loader", "Typosquat of babel-loader"},

	// TypeScript typosquats
	{regexp.MustCompile(`(?i)^typ3script$`), CategoryTyposquatted, 1.0, "typo_typ3script", "Typosquat of typescript (3)"},
	{regexp.MustCompile(`(?i)^typescrip$`), CategoryTyposquatted, 1.0, "typo_typescrip", "Typosquat of typescript (missing t)"},
	{regexp.MustCompile(`(?i)^typscript$`), CategoryTyposquatted, 1.0, "typo_typscript", "Typosquat of typescript (missing e)"},
	{regexp.MustCompile(`(?i)^@type/`), CategoryTyposquatted, 0.9, "typo_type", "Potential typosquat of @types (missing s)"},
	{regexp.MustCompile(`(?i)^ts-nodes$`), CategoryTyposquatted, 1.0, "typo_ts_nodes", "Typosquat of ts-node (plural)"},
	{regexp.MustCompile(`(?i)^tsnode$`), CategoryTyposquatted, 1.0, "typo_tsnode", "Typosquat of ts-node (no hyphen)"},

	// ESLint typosquats
	{regexp.MustCompile(`(?i)^3slint$`), CategoryTyposquatted, 1.0, "typo_3slint", "Typosquat of eslint (3)"},
	{regexp.MustCompile(`(?i)^eslnt$`), CategoryTyposquatted, 1.0, "typo_eslnt", "Typosquat of eslint (missing i)"},
	{regexp.MustCompile(`(?i)^eslintt$`), CategoryTyposquatted, 1.0, "typo_eslintt", "Typosquat of eslint (double t)"},
	{regexp.MustCompile(`(?i)^eslint-config-pretti3r$`), CategoryTyposquatted, 1.0, "typo_eslint_prettier", "Typosquat of eslint-config-prettier"},
	{regexp.MustCompile(`(?i)^pretti3r$`), CategoryTyposquatted, 1.0, "typo_prettier", "Typosquat of prettier (3)"},
	{regexp.MustCompile(`(?i)^pretier$`), CategoryTyposquatted, 1.0, "typo_pretier", "Typosquat of prettier (missing t)"},

	// Axios typosquats
	{regexp.MustCompile(`(?i)^axi0s$`), CategoryTyposquatted, 1.0, "typo_axi0s", "Typosquat of axios (0)"},
	{regexp.MustCompile(`(?i)^axois$`), CategoryTyposquatted, 1.0, "typo_axois", "Typosquat of axios (swap)"},
	{regexp.MustCompile(`(?i)^axioss$`), CategoryTyposquatted, 1.0, "typo_axioss", "Typosquat of axios (double s)"},
	{regexp.MustCompile(`(?i)^axi0s-mock-adapter$`), CategoryTyposquatted, 1.0, "typo_axios_mock", "Typosquat of axios-mock-adapter"},

	// Testing library typosquats
	{regexp.MustCompile(`(?i)^j3st$`), CategoryTyposquatted, 1.0, "typo_j3st", "Typosquat of jest (3)"},
	{regexp.MustCompile(`(?i)^jset$`), CategoryTyposquatted, 1.0, "typo_jset", "Typosquat of jest (swap)"},
	{regexp.MustCompile(`(?i)^jestt$`), CategoryTyposquatted, 1.0, "typo_jestt", "Typosquat of jest (double t)"},
	{regexp.MustCompile(`(?i)^m0cha$`), CategoryTyposquatted, 1.0, "typo_m0cha", "Typosquat of mocha (0)"},
	{regexp.MustCompile(`(?i)^mohca$`), CategoryTyposquatted, 1.0, "typo_mohca", "Typosquat of mocha (swap)"},
	{regexp.MustCompile(`(?i)^chais$`), CategoryTyposquatted, 0.9, "typo_chais", "Typosquat of chai (plural)"},
	{regexp.MustCompile(`(?i)^@testinglibrary/`), CategoryTyposquatted, 1.0, "typo_testing_lib", "Typosquat of @testing-library (no hyphen)"},
	{regexp.MustCompile(`(?i)^cypr3ss$`), CategoryTyposquatted, 1.0, "typo_cypr3ss", "Typosquat of cypress (3)"},
	{regexp.MustCompile(`(?i)^cypres$`), CategoryTyposquatted, 1.0, "typo_cypres", "Typosquat of cypress (missing s)"},

	// Database drivers typosquats
	{regexp.MustCompile(`(?i)^m0ngo$`), CategoryTyposquatted, 1.0, "typo_m0ngo", "Typosquat of mongo (0)"},
	{regexp.MustCompile(`(?i)^mongos$`), CategoryTyposquatted, 1.0, "typo_mongos", "Typosquat of mongo (plural)"},
	{regexp.MustCompile(`(?i)^mong0db$`), CategoryTyposquatted, 1.0, "typo_mong0db", "Typosquat of mongodb (0)"},
	{regexp.MustCompile(`(?i)^mongodb-$`), CategoryTyposquatted, 1.0, "typo_mongodb_hyphen", "Typosquat of mongodb (trailing hyphen)"},
	{regexp.MustCompile(`(?i)^mong00se$`), CategoryTyposquatted, 1.0, "typo_mong00se", "Typosquat of mongoose (00)"},
	{regexp.MustCompile(`(?i)^mongo0se$`), CategoryTyposquatted, 1.0, "typo_mongo0se", "Typosquat of mongoose (0)"},
	{regexp.MustCompile(`(?i)^mongose$`), CategoryTyposquatted, 1.0, "typo_mongose", "Typosquat of mongoose (missing o)"},
	{regexp.MustCompile(`(?i)^mysql3$`), CategoryTyposquatted, 0.9, "typo_mysql3", "Potential typosquat of mysql2"},
	{regexp.MustCompile(`(?i)^mysqll$`), CategoryTyposquatted, 0.9, "typo_mysqll", "Potential typosquat of mysql"},
	{regexp.MustCompile(`(?i)^p9$`), CategoryTyposquatted, 1.0, "typo_p9", "Typosquat of pg (9)"},
	{regexp.MustCompile(`(?i)^r3dis$`), CategoryTyposquatted, 1.0, "typo_r3dis", "Typosquat of redis (3)"},
	{regexp.MustCompile(`(?i)^redis-$`), CategoryTyposquatted, 1.0, "typo_redis_hyphen", "Typosquat of redis (trailing hyphen)"},
	{regexp.MustCompile(`(?i)^sequ3lize$`), CategoryTyposquatted, 1.0, "typo_sequ3lize", "Typosquat of sequelize (3)"},
	{regexp.MustCompile(`(?i)^sequalize$`), CategoryTyposquatted, 1.0, "typo_sequalize", "Typosquat of sequelize (a)"},
	{regexp.MustCompile(`(?i)^prisma-clients$`), CategoryTyposquatted, 1.0, "typo_prisma", "Typosquat of @prisma/client (plural)"},

	// Utility typosquats
	{regexp.MustCompile(`(?i)^momen7$`), CategoryTyposquatted, 1.0, "typo_momen7", "Typosquat of moment (7)"},
	{regexp.MustCompile(`(?i)^momnet$`), CategoryTyposquatted, 1.0, "typo_momnet", "Typosquat of moment (swap)"},
	{regexp.MustCompile(`(?i)^da7js$`), CategoryTyposquatted, 1.0, "typo_da7js", "Typosquat of dayjs (7)"},
	{regexp.MustCompile(`(?i)^daysjs$`), CategoryTyposquatted, 1.0, "typo_daysjs", "Typosquat of dayjs (extra s)"},
	{regexp.MustCompile(`(?i)^datefns$`), CategoryTyposquatted, 1.0, "typo_datefns", "Typosquat of date-fns (no hyphen)"},
	{regexp.MustCompile(`(?i)^date-fn$`), CategoryTyposquatted, 1.0, "typo_datefn", "Typosquat of date-fns (missing s)"},
	{regexp.MustCompile(`(?i)^uuids$`), CategoryTyposquatted, 0.9, "typo_uuids", "Potential typosquat of uuid (plural)"},
	{regexp.MustCompile(`(?i)^uui$`), CategoryTyposquatted, 0.9, "typo_uui", "Potential typosquat of uuid (missing d)"},
	{regexp.MustCompile(`(?i)^dot3nv$`), CategoryTyposquatted, 1.0, "typo_dot3nv", "Typosquat of dotenv (3)"},
	{regexp.MustCompile(`(?i)^dotnev$`), CategoryTyposquatted, 1.0, "typo_dotnev", "Typosquat of dotenv (swap)"},
	{regexp.MustCompile(`(?i)^chalks$`), CategoryTyposquatted, 0.9, "typo_chalks", "Potential typosquat of chalk (plural)"},
	{regexp.MustCompile(`(?i)^commanders$`), CategoryTyposquatted, 0.9, "typo_commanders", "Potential typosquat of commander (plural)"},
	{regexp.MustCompile(`(?i)^y@rgs$`), CategoryTyposquatted, 1.0, "typo_y@rgs", "Typosquat of yargs (@)"},
	{regexp.MustCompile(`(?i)^yarsg$`), CategoryTyposquatted, 1.0, "typo_yarsg", "Typosquat of yargs (swap)"},
	{regexp.MustCompile(`(?i)^inqu1rer$`), CategoryTyposquatted, 1.0, "typo_inqu1rer", "Typosquat of inquirer (1)"},
	{regexp.MustCompile(`(?i)^inqurer$`), CategoryTyposquatted, 1.0, "typo_inqurer", "Typosquat of inquirer (missing i)"},

	// Cross-env typosquatting (known attack vector)
	{regexp.MustCompile(`(?i)^cross-3nv$`), CategoryTyposquatted, 1.0, "typo_cross3nv", "Typosquat of cross-env (3)"},
	{regexp.MustCompile(`(?i)^crossenv$`), CategoryTyposquatted, 1.0, "typo_crossenv", "Typosquat of cross-env (no hyphen - known malicious)"},
	{regexp.MustCompile(`(?i)^cross_env$`), CategoryTyposquatted, 1.0, "typo_cross_env", "Typosquat of cross-env (underscore)"},

	// Known malicious/compromised packages
	{regexp.MustCompile(`(?i)^coa$`), CategoryMalicious, 1.0, "malicious_coa", "Known malicious package"},
	{regexp.MustCompile(`(?i)^rc$`), CategoryMalicious, 1.0, "malicious_rc", "Known malicious package"},
	{regexp.MustCompile(`(?i)^ua-parser-js$`), CategoryMalicious, 0.7, "malicious_ua_parser", "Package with compromised versions - verify version"},
	{regexp.MustCompile(`(?i)^event-stream$`), CategoryMalicious, 0.7, "malicious_event_stream", "Package with compromised versions - verify version"},
	{regexp.MustCompile(`(?i)^flatmap-stream$`), CategoryMalicious, 1.0, "malicious_flatmap_stream", "Known malicious package"},

	// ==========================================
	// CATEGORY: Known Malicious MCP Servers (26 patterns)
	// ==========================================

	// Crypto mining MCP servers
	{regexp.MustCompile(`(?i)^mcp-?miner`), CategoryCryptojacker, 1.0, "mcp_miner", "Crypto mining MCP server"},
	{regexp.MustCompile(`(?i)^mcp-?crypto-?mine`), CategoryCryptojacker, 1.0, "mcp_crypto_mine", "Crypto mining MCP server"},
	{regexp.MustCompile(`(?i)^mcp-?xmr`), CategoryCryptojacker, 1.0, "mcp_xmr", "Monero mining MCP server"},
	{regexp.MustCompile(`(?i)^mcp-?coinhive`), CategoryCryptojacker, 1.0, "mcp_coinhive", "CoinHive mining MCP server"},
	{regexp.MustCompile(`(?i)monero|xmrig|nicehash`), CategoryCryptojacker, 0.9, "mcp_mining_keywords", "Mining-related keywords"},

	// Data exfiltration MCP servers
	{regexp.MustCompile(`(?i)^mcp-?exfil`), CategoryExfiltration, 1.0, "mcp_exfil", "Data exfiltration MCP server"},
	{regexp.MustCompile(`(?i)^mcp-?steal`), CategoryExfiltration, 1.0, "mcp_steal", "Data stealing MCP server"},
	{regexp.MustCompile(`(?i)^mcp-?dump`), CategoryExfiltration, 0.9, "mcp_dump", "Data dumping MCP server"},
	{regexp.MustCompile(`(?i)^mcp-?harvest`), CategoryExfiltration, 1.0, "mcp_harvest", "Data harvesting MCP server"},
	{regexp.MustCompile(`(?i)^mcp-?scrape-?secrets`), CategoryExfiltration, 1.0, "mcp_scrape_secrets", "Secret scraping MCP server"},
	{regexp.MustCompile(`(?i)^mcp-?env-?dump`), CategoryExfiltration, 1.0, "mcp_env_dump", "Environment dumping MCP server"},
	{regexp.MustCompile(`(?i)^mcp-?credential`), CategoryCredStealer, 1.0, "mcp_credential", "Credential stealing MCP server"},
	{regexp.MustCompile(`(?i)^mcp-?keylog`), CategoryCredStealer, 1.0, "mcp_keylog", "Keylogging MCP server"},
	{regexp.MustCompile(`(?i)^mcp-?password`), CategoryCredStealer, 0.9, "mcp_password", "Password related MCP server"},

	// Backdoor MCP servers
	{regexp.MustCompile(`(?i)^mcp-?backdoor`), CategoryBackdoor, 1.0, "mcp_backdoor", "Backdoor MCP server"},
	{regexp.MustCompile(`(?i)^mcp-?shell`), CategoryBackdoor, 1.0, "mcp_shell", "Shell access MCP server"},
	{regexp.MustCompile(`(?i)^mcp-?reverse`), CategoryBackdoor, 1.0, "mcp_reverse", "Reverse shell MCP server"},
	{regexp.MustCompile(`(?i)^mcp-?rat`), CategoryBackdoor, 1.0, "mcp_rat", "Remote access trojan MCP server"},
	{regexp.MustCompile(`(?i)^mcp-?c2`), CategoryBackdoor, 1.0, "mcp_c2", "Command & control MCP server"},
	{regexp.MustCompile(`(?i)^mcp-?beacon`), CategoryBackdoor, 1.0, "mcp_beacon", "Beacon MCP server"},
	{regexp.MustCompile(`(?i)^mcp-?implant`), CategoryBackdoor, 1.0, "mcp_implant", "Implant MCP server"},

	// Destructive MCP servers
	{regexp.MustCompile(`(?i)^mcp-?wipe`), CategoryDestructive, 1.0, "mcp_wipe", "Data wiping MCP server"},
	{regexp.MustCompile(`(?i)^mcp-?destroy`), CategoryDestructive, 1.0, "mcp_destroy", "Destructive MCP server"},
	{regexp.MustCompile(`(?i)^mcp-?ransom`), CategoryDestructive, 1.0, "mcp_ransom", "Ransomware MCP server"},
	{regexp.MustCompile(`(?i)^mcp-?encrypt`), CategoryDestructive, 0.8, "mcp_encrypt", "Potentially destructive encryption MCP"},
	{regexp.MustCompile(`(?i)^mcp-?locker`), CategoryDestructive, 1.0, "mcp_locker", "System locker MCP server"},

	// ==========================================
	// CATEGORY: Dangerous shell commands (43 patterns)
	// ==========================================

	// Root/sudo access
	{regexp.MustCompile(`(?i)sudo\s+-?i`), CategoryDangerous, 0.9, "sudo_interactive", "Interactive sudo session"},
	{regexp.MustCompile(`(?i)sudo\s+su(\s|$)`), CategoryDangerous, 0.9, "sudo_su", "Sudo to root"},
	{regexp.MustCompile(`(?i)su\s+-\s*$`), CategoryDangerous, 0.9, "su_root", "Switch to root"},
	{regexp.MustCompile(`(?i)sudo\s+bash`), CategoryDangerous, 0.9, "sudo_bash", "Sudo bash"},
	{regexp.MustCompile(`(?i)sudo\s+sh`), CategoryDangerous, 0.9, "sudo_sh", "Sudo shell"},

	// Destructive file operations
	{regexp.MustCompile(`(?i)rm\s+-rf\s+/`), CategoryDestructive, 1.0, "rm_rf_root", "Recursive delete root"},
	{regexp.MustCompile(`(?i)rm\s+-rf\s+~`), CategoryDestructive, 1.0, "rm_rf_home", "Recursive delete home"},
	{regexp.MustCompile(`(?i)rm\s+-rf\s+\*`), CategoryDestructive, 0.9, "rm_rf_all", "Recursive delete all"},
	{regexp.MustCompile(`(?i)rm\s+-rf\s+\.`), CategoryDestructive, 0.9, "rm_rf_cwd", "Recursive delete cwd"},
	{regexp.MustCompile(`(?i)mkfs\s`), CategoryDestructive, 1.0, "mkfs", "Format filesystem"},
	{regexp.MustCompile(`(?i)dd\s+if=.+of=/dev/`), CategoryDestructive, 1.0, "dd_overwrite", "DD overwrite device"},
	{regexp.MustCompile(`(?i)dd\s+of=/dev/sd`), CategoryDestructive, 1.0, "dd_disk", "DD write to disk"},
	{regexp.MustCompile(`(?i)shred\s+-`), CategoryDestructive, 0.9, "shred", "Secure file deletion"},
	{regexp.MustCompile(`(?i)wipefs\s`), CategoryDestructive, 1.0, "wipefs", "Wipe filesystem signatures"},
	{regexp.MustCompile(`(?i)fdisk\s+-`), CategoryDestructive, 0.9, "fdisk", "Disk partitioning"},
	{regexp.MustCompile(`(?i)parted\s+-`), CategoryDestructive, 0.9, "parted", "Disk partitioning"},

	// Network exfiltration
	{regexp.MustCompile(`(?i)curl[^\n]*-d\s+@\S*(?:/etc/(?:passwd|shadow)|\.ssh/|\.aws/|\.env\b|id_rsa|credentials|secrets?)`), CategoryExfiltration, 0.9, "curl_file_upload", "Curl file upload of sensitive file"},
	{regexp.MustCompile(`(?i)curl.*/etc/(passwd|shadow|hosts)`), CategoryExfiltration, 1.0, "curl_system_files", "Curl system file exfil"},
	{regexp.MustCompile(`(?i)wget.*-O\s+-.*\|\s*(bash|sh)`), CategoryBackdoor, 1.0, "wget_pipe_shell", "Wget pipe to shell"},
	{regexp.MustCompile(`(?i)curl.*\|\s*(bash|sh)`), CategoryBackdoor, 1.0, "curl_pipe_shell", "Curl pipe to shell"},
	{regexp.MustCompile(`(?i)nc\s+-e\s+/(bin/)?(bash|sh)`), CategoryBackdoor, 1.0, "nc_bind_shell", "Netcat bind shell"},
	{regexp.MustCompile(`(?i)nc\s+-l.*-p.*-e`), CategoryBackdoor, 1.0, "nc_listener", "Netcat listener with exec"},
	{regexp.MustCompile(`(?i)/dev/tcp/`), CategoryBackdoor, 1.0, "dev_tcp", "Bash tcp device"},

	// Cron/persistence
	{regexp.MustCompile(`(?i)crontab\s+-e`), CategoryDangerous, 0.8, "crontab_edit", "Edit crontab"},
	{regexp.MustCompile(`(?i)echo.*>>\s*/etc/cron`), CategoryBackdoor, 1.0, "cron_persist", "Cron persistence"},
	{regexp.MustCompile(`(?i)>\s*~/.bashrc`), CategoryBackdoor, 0.9, "bashrc_overwrite", "Bashrc overwrite"},
	{regexp.MustCompile(`(?i)>>\s*~/.bashrc`), CategoryBackdoor, 0.9, "bashrc_append", "Bashrc append"},
	{regexp.MustCompile(`(?i)>\s*~/.profile`), CategoryBackdoor, 0.9, "profile_overwrite", "Profile overwrite"},

	// SSH manipulation
	{regexp.MustCompile(`(?i)>\s*~/.ssh/authorized_keys`), CategoryBackdoor, 1.0, "ssh_key_overwrite", "SSH key overwrite"},
	{regexp.MustCompile(`(?i)>>\s*~/.ssh/authorized_keys`), CategoryBackdoor, 1.0, "ssh_key_add", "SSH key addition"},
	{regexp.MustCompile(`(?i)cat\s+~/.ssh/id_`), CategoryExfiltration, 0.9, "ssh_key_read", "SSH key read"},
	{regexp.MustCompile(`(?i)ssh-keygen.*-t.*-N\s*["']?["']?`), CategorySuspicious, 0.7, "ssh_keygen_no_pass", "SSH keygen no passphrase"},

	// Process/system manipulation
	{regexp.MustCompile(`(?i)kill\s+-9\s+-1`), CategoryDestructive, 1.0, "kill_all", "Kill all processes"},
	{regexp.MustCompile(`(?i)pkill\s+-9`), CategoryDangerous, 0.8, "pkill_force", "Force kill processes"},
	{regexp.MustCompile(`(?i)killall\s+-9`), CategoryDangerous, 0.8, "killall_force", "Force kill all processes"},
	{regexp.MustCompile(`:\(\)\s*\{\s*:\|\s*:&\s*\}\s*;\s*:`), CategoryDestructive, 1.0, "fork_bomb", "Fork bomb"},
	{regexp.MustCompile(`(?i)chmod\s+[0-7]*777`), CategoryDangerous, 0.8, "chmod_777", "World writable permissions"},
	{regexp.MustCompile(`(?i)chmod\s+u\+s`), CategoryDangerous, 0.9, "setuid", "SetUID bit"},
	{regexp.MustCompile(`(?i)chown\s+root`), CategoryDangerous, 0.8, "chown_root", "Change owner to root"},

	// Environment manipulation
	{regexp.MustCompile(`(?i)export\s+LD_PRELOAD`), CategoryBackdoor, 1.0, "ld_preload", "LD_PRELOAD hijacking"},
	{regexp.MustCompile(`(?i)export\s+PATH=`), CategorySuspicious, 0.7, "path_override", "PATH override"},
	{regexp.MustCompile(`(?i)unset\s+HISTFILE`), CategorySuspicious, 0.9, "unset_histfile", "Hide command history"},
	{regexp.MustCompile(`(?i)HISTSIZE=0`), CategorySuspicious, 0.9, "clear_history", "Clear history"},

	// ==========================================
	// CATEGORY: Malicious file patterns (13 patterns)
	// ==========================================

	// Executable downloads
	{regexp.MustCompile(`(?i)\.(exe|bat|cmd|ps1|vbs|jar|msi)$`), CategorySuspicious, 0.8, "executable_ext", "Executable file extension"},
	{regexp.MustCompile(`(?i)\.(elf|bin|so|dylib)$`), CategorySuspicious, 0.7, "binary_ext", "Binary file extension"},
	{regexp.MustCompile(`(?i)\.php[0-9]?$`), CategorySuspicious, 0.6, "php_ext", "PHP file"},
	{regexp.MustCompile(`(?i)\.jsp[x]?$`), CategorySuspicious, 0.6, "jsp_ext", "JSP file"},
	{regexp.MustCompile(`(?i)\.asp[x]?$`), CategorySuspicious, 0.6, "asp_ext", "ASP file"},

	// Webshells
	{regexp.MustCompile(`(?i)c99|r57|b374k|wso|webshell|backdoor`), CategoryBackdoor, 1.0, "webshell_name", "Known webshell name"},
	{regexp.MustCompile(`(?i)eval\s*\(\s*\$_(GET|POST|REQUEST)`), CategoryBackdoor, 1.0, "php_eval_input", "PHP eval input"},
	{regexp.MustCompile(`(?i)system\s*\(\s*\$_(GET|POST|REQUEST)`), CategoryBackdoor, 1.0, "php_system_input", "PHP system input"},
	{regexp.MustCompile(`(?i)passthru\s*\(\s*\$_(GET|POST|REQUEST)`), CategoryBackdoor, 1.0, "php_passthru_input", "PHP passthru input"},
	{regexp.MustCompile(`(?i)shell_exec\s*\(\s*\$_(GET|POST|REQUEST)`), CategoryBackdoor, 1.0, "php_shell_exec_input", "PHP shell_exec input"},

	// Malicious domains/IPs
	{regexp.MustCompile(`(?i)(pastebin|ghostbin|hastebin)\.com`), CategorySuspicious, 0.7, "paste_site", "Paste site (common for malware)"},
	{regexp.MustCompile(`(?i)\.onion$`), CategorySuspicious, 0.8, "onion_domain", "Tor hidden service"},
	{regexp.MustCompile(`(?i)bit\.ly|tinyurl|t\.co|goo\.gl`), CategorySuspicious, 0.6, "url_shortener", "URL shortener"},

	// ==========================================
	// CATEGORY: Suspicious MCP tool names (53 patterns)
	// ==========================================

	// Generic suspicious names
	{regexp.MustCompile(`(?i)^tool[-_]?(hack|exploit|pwn|crack|brute)`), CategoryMalicious, 1.0, "suspicious_tool_name", "Suspicious tool name"},
	{regexp.MustCompile(`(?i)^(hack|exploit|pwn|crack|brute)[-_]?tool`), CategoryMalicious, 1.0, "malicious_tool_prefix", "Malicious tool prefix"},
	{regexp.MustCompile(`(?i)password[-_]?(crack|brute|dump|steal)`), CategoryCredStealer, 1.0, "password_attack", "Password attack tool"},
	{regexp.MustCompile(`(?i)(token|jwt|session)[-_]?(steal|hijack|forge)`), CategoryCredStealer, 1.0, "token_attack", "Token attack tool"},
	{regexp.MustCompile(`(?i)bypass[-_]?(auth|login|2fa|mfa)`), CategoryMalicious, 1.0, "auth_bypass", "Auth bypass tool"},
	{regexp.MustCompile(`(?i)sql[-_]?(inject|dump|brute)`), CategoryMalicious, 1.0, "sql_attack", "SQL attack tool"},
	{regexp.MustCompile(`(?i)xss[-_]?(inject|payload|exploit)`), CategoryMalicious, 1.0, "xss_attack", "XSS attack tool"},
	{regexp.MustCompile(`(?i)rce[-_]?(exploit|payload|tool)`), CategoryMalicious, 1.0, "rce_tool", "RCE tool"},
	{regexp.MustCompile(`(?i)lfi[-_]?(exploit|tool)`), CategoryMalicious, 1.0, "lfi_tool", "LFI exploit tool"},
	{regexp.MustCompile(`(?i)rfi[-_]?(exploit|tool)`), CategoryMalicious, 1.0, "rfi_tool", "RFI exploit tool"},
	{regexp.MustCompile(`(?i)ssrf[-_]?(exploit|tool)`), CategoryMalicious, 1.0, "ssrf_tool", "SSRF exploit tool"},
	{regexp.MustCompile(`(?i)xxe[-_]?(exploit|tool)`), CategoryMalicious, 1.0, "xxe_tool", "XXE exploit tool"},
	{regexp.MustCompile(`(?i)deserialization[-_]?(exploit|tool)`), CategoryMalicious, 1.0, "deser_tool", "Deserialization exploit"},
	{regexp.MustCompile(`(?i)privilege[-_]?(escal|escalation)`), CategoryMalicious, 1.0, "privesc_tool", "Privilege escalation tool"},
	{regexp.MustCompile(`(?i)(kernel|root)[-_]?exploit`), CategoryMalicious, 1.0, "kernel_exploit", "Kernel exploit tool"},
	{regexp.MustCompile(`(?i)zero[-_]?day`), CategoryMalicious, 1.0, "zeroday_tool", "Zero-day tool"},
	{regexp.MustCompile(`(?i)cve[-_]?(exploit|poc)`), CategoryMalicious, 0.9, "cve_exploit", "CVE exploit tool"},
	{regexp.MustCompile(`(?i)vulnerability[-_]?scanner`), CategorySuspicious, 0.7, "vuln_scanner", "Vulnerability scanner"},
	{regexp.MustCompile(`(?i)port[-_]?scanner`), CategorySuspicious, 0.6, "port_scanner", "Port scanner"},
	{regexp.MustCompile(`(?i)network[-_]?scan`), CategorySuspicious, 0.6, "network_scanner", "Network scanner"},
	{regexp.MustCompile(`(?i)subdomain[-_]?(enum|finder|brute)`), CategorySuspicious, 0.7, "subdomain_enum", "Subdomain enumeration"},
	{regexp.MustCompile(`(?i)directory[-_]?(brute|buster|enum)`), CategorySuspicious, 0.7, "dir_bruteforce", "Directory bruteforce"},
	{regexp.MustCompile(`(?i)fuzzer|fuzzing`), CategorySuspicious, 0.6, "fuzzer_tool", "Fuzzing tool"},
	{regexp.MustCompile(`(?i)payload[-_]?generator`), CategoryMalicious, 0.9, "payload_gen", "Payload generator"},
	{regexp.MustCompile(`(?i)shellcode[-_]?(gen|generator)`), CategoryMalicious, 1.0, "shellcode_gen", "Shellcode generator"},
	{regexp.MustCompile(`(?i)reverse[-_]?shell`), CategoryBackdoor, 1.0, "reverse_shell_tool", "Reverse shell tool"},
	{regexp.MustCompile(`(?i)bind[-_]?shell`), CategoryBackdoor, 1.0, "bind_shell_tool", "Bind shell tool"},
	{regexp.MustCompile(`(?i)web[-_]?shell`), CategoryBackdoor, 1.0, "web_shell_tool", "Web shell tool"},
	{regexp.MustCompile(`(?i)rootkit`), CategoryMalicious, 1.0, "rootkit_tool", "Rootkit tool"},
	{regexp.MustCompile(`(?i)keylogger`), CategoryCredStealer, 1.0, "keylogger_tool", "Keylogger tool"},
	{regexp.MustCompile(`(?i)spyware`), CategoryMalicious, 1.0, "spyware_tool", "Spyware tool"},
	{regexp.MustCompile(`(?i)ransomware`), CategoryDestructive, 1.0, "ransomware_tool", "Ransomware tool"},
	{regexp.MustCompile(`(?i)trojan`), CategoryMalicious, 1.0, "trojan_tool", "Trojan tool"},
	{regexp.MustCompile(`(?i)botnet`), CategoryMalicious, 1.0, "botnet_tool", "Botnet tool"},
	{regexp.MustCompile(`(?i)ddos`), CategoryDestructive, 1.0, "ddos_tool", "DDoS tool"},
	{regexp.MustCompile(`(?i)dos[-_]?attack`), CategoryDestructive, 1.0, "dos_attack_tool", "DoS attack tool"},
	{regexp.MustCompile(`(?i)flood[-_]?(attack|tool)`), CategoryDestructive, 1.0, "flood_tool", "Flood attack tool"},
	{regexp.MustCompile(`(?i)stress[-_]?test`), CategorySuspicious, 0.6, "stress_test", "Stress testing tool"},
	{regexp.MustCompile(`(?i)load[-_]?test`), CategorySuspicious, 0.5, "load_test", "Load testing tool"},

	// Known malicious tool names
	{regexp.MustCompile(`(?i)metasploit|msfvenom|meterpreter`), CategoryMalicious, 1.0, "metasploit", "Metasploit framework"},
	{regexp.MustCompile(`(?i)cobalt[-_]?strike|beacon`), CategoryMalicious, 1.0, "cobalt_strike", "Cobalt Strike"},
	{regexp.MustCompile(`(?i)empire|starkiller`), CategoryMalicious, 0.9, "empire_c2", "Empire C2 framework"},
	{regexp.MustCompile(`(?i)mimikatz|sekurlsa`), CategoryCredStealer, 1.0, "mimikatz", "Mimikatz"},
	{regexp.MustCompile(`(?i)bloodhound|sharphound`), CategoryMalicious, 0.9, "bloodhound", "BloodHound"},
	{regexp.MustCompile(`(?i)nmap|masscan|zmap`), CategorySuspicious, 0.6, "network_scanner_known", "Known network scanner"},
	{regexp.MustCompile(`(?i)burp[-_]?suite`), CategorySuspicious, 0.5, "burp_suite", "Burp Suite"},
	{regexp.MustCompile(`(?i)sqlmap`), CategoryMalicious, 0.9, "sqlmap", "SQLMap"},
	{regexp.MustCompile(`(?i)nikto|wpscan|dirb|gobuster`), CategorySuspicious, 0.7, "web_scanner", "Web vulnerability scanner"},
	{regexp.MustCompile(`(?i)hydra|medusa|ncrack`), CategoryCredStealer, 1.0, "password_bruter", "Password bruteforce tool"},
	{regexp.MustCompile(`(?i)john[-_]?the[-_]?ripper|hashcat`), CategoryCredStealer, 0.9, "password_cracker", "Password cracker"},
	{regexp.MustCompile(`(?i)aircrack|reaver|bully`), CategoryMalicious, 1.0, "wifi_attack", "WiFi attack tool"},
	{regexp.MustCompile(`(?i)ettercap|bettercap|arpspoof`), CategoryMalicious, 1.0, "mitm_tool", "MITM attack tool"},
	{regexp.MustCompile(`(?i)wireshark|tcpdump|tshark`), CategorySuspicious, 0.5, "packet_capture", "Packet capture tool"},

	// ==========================================
	// CATEGORY: Suspicious URL patterns (6 patterns)
	// ==========================================

	// Raw IP addresses
	{regexp.MustCompile(`(?i)https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}`), CategorySuspicious, 0.7, "raw_ip_url", "URL with raw IP address"},

	// Suspicious TLDs
	{regexp.MustCompile(`(?i)\.(xyz|top|pw|tk|ml|ga|cf|gq|work|click|link|download)$`), CategorySuspicious, 0.6, "suspicious_tld", "Suspicious TLD"},

	// Phishing patterns
	{regexp.MustCompile(`(?i)(login|signin|account|verify|secure|update)[-_.]?(your)?[-_.]?(account|password|info)`), CategoryMalicious, 0.8, "phishing_url", "Potential phishing URL"},
	// Typosquat / impersonation shape: brand glued to a security/verify word
	// (paypal-secure, apple-verify-login), NOT a legitimate brand domain like
	// google.com. Requires the deceptive suffix, so "host google.com" is not flagged.
	{regexp.MustCompile(`(?i)\b(paypal|google|microsoft|apple|amazon|facebook|instagram|twitter)[-_](?:secure|verify|login|signin|account|support|update|confirm|billing|alert)`), CategorySuspicious, 0.7, "brand_impersonation", "Brand impersonation"},
	{regexp.MustCompile(`(?i)www\d+\.`), CategorySuspicious, 0.6, "numbered_www", "Numbered www subdomain"},

	// Data URI
	{regexp.MustCompile(`(?i)^data:.*base64`), CategorySuspicious, 0.7, "data_uri_base64", "Base64 data URI"},

	// ==========================================
	// CATEGORY: Dangerous API endpoints (15 patterns)
	// ==========================================

	// Admin/internal endpoints
	{regexp.MustCompile(`(?i)/admin/`), CategoryDangerous, 0.7, "admin_endpoint", "Admin endpoint"},
	{regexp.MustCompile(`(?i)/debug/`), CategoryDangerous, 0.8, "debug_endpoint", "Debug endpoint"},
	{regexp.MustCompile(`(?i)/internal/`), CategoryDangerous, 0.8, "internal_endpoint", "Internal endpoint"},
	{regexp.MustCompile(`(?i)/management/`), CategoryDangerous, 0.7, "management_endpoint", "Management endpoint"},
	{regexp.MustCompile(`(?i)/actuator/`), CategoryDangerous, 0.8, "actuator_endpoint", "Spring Actuator endpoint"},
	{regexp.MustCompile(`(?i)/\.env`), CategoryExfiltration, 1.0, "env_file", "Environment file access"},
	{regexp.MustCompile(`(?i)/\.git/`), CategoryExfiltration, 1.0, "git_dir", "Git directory access"},
	{regexp.MustCompile(`(?i)/\.svn/`), CategoryExfiltration, 1.0, "svn_dir", "SVN directory access"},
	{regexp.MustCompile(`(?i)/wp-config\.php`), CategoryExfiltration, 1.0, "wp_config", "WordPress config access"},
	{regexp.MustCompile(`(?i)/config\.(json|yaml|yml|xml|ini)`), CategorySuspicious, 0.8, "config_file", "Config file access"},
	{regexp.MustCompile(`(?i)/backup\.(sql|zip|tar|gz)`), CategoryExfiltration, 1.0, "backup_file", "Backup file access"},
	{regexp.MustCompile(`(?i)/(dump|backup|export)\.(sql|db|sqlite)`), CategoryExfiltration, 1.0, "db_dump", "Database dump access"},

	// Cloud metadata endpoints
	{regexp.MustCompile(`(?i)169\.254\.169\.254`), CategoryExfiltration, 1.0, "aws_metadata", "AWS metadata endpoint"},
	{regexp.MustCompile(`(?i)metadata\.google\.internal`), CategoryExfiltration, 1.0, "gcp_metadata", "GCP metadata endpoint"},
	{regexp.MustCompile(`(?i)100\.100\.100\.200`), CategoryExfiltration, 1.0, "alibaba_metadata", "Alibaba metadata endpoint"},

	// ==========================================
	// CATEGORY: Known malicious file hashes (placeholder - expandable)
	// ==========================================
	// Note: In production, this would be populated with actual malicious file hashes

	{regexp.MustCompile(`(?i)^[a-f0-9]{64}$`), CategorySuspicious, 0.1, "sha256_hash", "SHA256 hash pattern"},
	{regexp.MustCompile(`(?i)^[a-f0-9]{32}$`), CategorySuspicious, 0.1, "md5_hash", "MD5 hash pattern"},
}

// CheckBlockedTool checks if a tool/skill name is blocked.
func CheckBlockedTool(name string) *BlockedToolResult {
	result := &BlockedToolResult{
		Blocked: false,
		Score:   0.0,
	}

	if name == "" {
		return result
	}

	// Normalize the name
	nameLower := strings.ToLower(strings.TrimSpace(name))

	// Check against patterns
	var bestMatch *BlockedToolPattern
	for i := range BlockedToolPatterns {
		pattern := &BlockedToolPatterns[i]
		if pattern.Pattern.MatchString(nameLower) {
			if bestMatch == nil || pattern.Severity > bestMatch.Severity {
				bestMatch = pattern
			}
		}
	}

	if bestMatch != nil {
		result.Blocked = bestMatch.Severity >= 0.8 // Block if severity >= 0.8
		result.Score = bestMatch.Severity
		result.Category = bestMatch.Category
		result.PatternName = bestMatch.Name
		result.Reason = bestMatch.Description
	}

	return result
}

// CheckBlockedToolInput checks all string values in a map for blocked tools.
func CheckBlockedToolInput(input map[string]any) *BlockedToolResult {
	worstResult := &BlockedToolResult{}
	walkMapStrings(input, func(s string) {
		if worstResult.Blocked {
			return
		}
		result := CheckBlockedTool(s)
		if result.Blocked || result.Score > worstResult.Score {
			worstResult = result
		}
	})
	return worstResult
}

// GetBlockedToolPatternCount returns the total number of blocked tool patterns.
func GetBlockedToolPatternCount() int {
	return len(BlockedToolPatterns)
}
