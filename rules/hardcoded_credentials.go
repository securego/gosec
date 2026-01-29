// (c) Copyright 2016 Hewlett Packard Enterprise Development LP
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package rules

import (
	"fmt"
	"go/ast"
	"go/token"
	"math"
	"regexp"
	"strconv"
	"strings"
	"unicode"

	zxcvbn "github.com/ccojocar/zxcvbn-go"

	"github.com/securego/gosec/v2"
	"github.com/securego/gosec/v2/issue"
)

type secretPattern struct {
	name   string
	regexp *regexp.Regexp
}

// entropyCacheKey is the cache key for entropy analysis results.
type entropyCacheKey string

// secretPatternCacheKey is the cache key for secret pattern scan results.
type secretPatternCacheKey string

// stringStats holds metrics and flags for a token analysis.
type stringStats struct {
	// Metrics
	length  int
	digits  int
	symbols int

	// Character Flags (Avoids strings.Contains)
	hasUpper      bool
	hasNonASCII   bool
	hasSpace      bool
	hasDot        bool
	hasDash       bool
	hasUnderscore bool
	hasColon      bool
	hasBackslash  bool
	hasSlash      bool
	hasNewline    bool
	hasEqual      bool

	// Structure Flags
	isStructure bool // True if (Balanced && has Pairs) OR (has Newlines)
}

const uuidLength = 36

var secretsPatterns = [...]secretPattern{
	{
		name:   "RSA private key",
		regexp: regexp.MustCompile(`-----BEGIN RSA PRIVATE KEY-----`),
	},
	{
		name:   "SSH (DSA) private key",
		regexp: regexp.MustCompile(`-----BEGIN DSA PRIVATE KEY-----`),
	},
	{
		name:   "SSH (EC) private key",
		regexp: regexp.MustCompile(`-----BEGIN EC PRIVATE KEY-----`),
	},
	{
		name:   "PGP private key block",
		regexp: regexp.MustCompile(`-----BEGIN PGP PRIVATE KEY BLOCK-----`),
	},
	{
		name:   "Slack Token",
		regexp: regexp.MustCompile(`xox[pborsa]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-z0-9]{32}`),
	},
	{
		name:   "AWS API Key",
		regexp: regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
	},
	{
		name:   "Amazon MWS Auth Token",
		regexp: regexp.MustCompile(`amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`),
	},
	{
		name:   "AWS AppSync GraphQL Key",
		regexp: regexp.MustCompile(`da2-[a-z0-9]{26}`),
	},
	{
		name:   "GitHub personal access token",
		regexp: regexp.MustCompile(`ghp_[a-zA-Z0-9]{36}`),
	},
	{
		name:   "GitHub fine-grained access token",
		regexp: regexp.MustCompile(`github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59}`),
	},
	{
		name:   "GitHub action temporary token",
		regexp: regexp.MustCompile(`ghs_[a-zA-Z0-9]{36}`),
	},
	{
		name:   "Google API Key", // Also Google Cloud Platform, Gmail, Drive, YouTube, etc.
		regexp: regexp.MustCompile(`AIza[0-9A-Za-z\-_]{35}`),
	},

	{
		name:   "Google Cloud Platform OAuth", // Also Gmail, Drive, YouTube, etc.
		regexp: regexp.MustCompile(`[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com`),
	},

	{
		name:   "Google (GCP) Service-account",
		regexp: regexp.MustCompile(`"type": "service_account"`),
	},

	{
		name:   "Google OAuth Access Token",
		regexp: regexp.MustCompile(`ya29\.[0-9A-Za-z\-_]+`),
	},

	{
		name:   "Generic API Key",
		regexp: regexp.MustCompile(`[aA][pP][iI]_?[kK][eE][yY].*[''|"][0-9a-zA-Z]{32,45}[''|"]`),
	},
	{
		name:   "Generic Secret",
		regexp: regexp.MustCompile(`[sS][eE][cC][rR][eE][tT].*[''|"][0-9a-zA-Z]{32,45}[''|"]`),
	},
	{
		name:   "Heroku API Key",
		regexp: regexp.MustCompile(`[hH][eE][rR][oO][kK][uU].*[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}`),
	},
	{
		name:   "MailChimp API Key",
		regexp: regexp.MustCompile(`[0-9a-f]{32}-us[0-9]{1,2}`),
	},
	{
		name:   "Mailgun API Key",
		regexp: regexp.MustCompile(`key-[0-9a-zA-Z]{32}`),
	},
	{
		name:   "Password in URL",
		regexp: regexp.MustCompile(`[a-zA-Z]{3,10}://[a-zA-Z0-9\.\-\_\+]{1,64}:[a-zA-Z0-9\.\-\_\!\$\%\&\*\+\=\^\(\)]{1,128}@[a-zA-Z0-9\.\-\_]+(:[0-9]+)?(/[^"'\s]*)?(["'\s]|$)`),
	},
	{
		name:   "Slack Webhook",
		regexp: regexp.MustCompile(`https://hooks\.slack\.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}`),
	},
	{
		name:   "Stripe API Key",
		regexp: regexp.MustCompile(`sk_live_[0-9a-zA-Z]{24}`),
	},
	{
		name:   "Stripe Restricted API Key",
		regexp: regexp.MustCompile(`rk_live_[0-9a-zA-Z]{24}`),
	},
	{
		name:   "Square Access Token",
		regexp: regexp.MustCompile(`sq0atp-[0-9A-Za-z\-_]{22}`),
	},
	{
		name:   "Square OAuth Secret",
		regexp: regexp.MustCompile(`sq0csp-[0-9A-Za-z\-_]{43}`),
	},
	{
		name:   "Telegram Bot API Key",
		regexp: regexp.MustCompile(`[0-9]+:AA[0-9A-Za-z\-_]{33}`),
	},
	{
		name:   "Twilio API Key",
		regexp: regexp.MustCompile(`SK[0-9a-fA-F]{32}`),
	},
	{
		name:   "Twitter Access Token",
		regexp: regexp.MustCompile(`[tT][wW][iI][tT][tT][eE][rR].*[1-9][0-9]+-[0-9a-zA-Z]{40}`),
	},
	{
		name:   "Twitter OAuth",
		regexp: regexp.MustCompile(`[tT][wW][iI][tT][tT][eE][rR].*[''|"][0-9a-zA-Z]{35,44}[''|"]`),
	},
}

var (
	tokenRegex          = regexp.MustCompile(`[\p{L}\p{N}\p{Sc}\p{So}\p{M}\+\/=_\-\.!@#\$%^&\*\?~]{8,}`)
	codeRegex           = regexp.MustCompile(`^[a-zA-Z]+(?:[A-Z][a-z0-9]*)*$`)
	upperCaseConstRegex = regexp.MustCompile(`^[A-Z][A-Z0-9_]*[A-Z0-9]$`)
	headerRegex         = regexp.MustCompile(`(?i)^x-[a-z0-9-_]*[a-z0-9]$`)
	safeNameRegex       = regexp.MustCompile(`(?i)(env|path|dir|param|mode|type|flag|config|setting|option|prop|attr)`)
	sqlPlaceholderRegex = regexp.MustCompile(`(\bvalues\s*\(.*(\?|\$\d+)|=\s*(\?|\$\d+)|\bidentified\s+by\s*(\?|\$\d+))`)
	safeURLRegex        = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9+.-]*://[^?]*$`)
	pathRegex           = regexp.MustCompile(`^/?([a-zA-Z0-9._-]+/)+[a-zA-Z0-9._-]+$`)
	identifierRegex     = regexp.MustCompile(`^#?[a-zA-Z0-9_\-\.:/\\\(\)\[\]\{\}]+$`)
	weakIdentifierRegex = regexp.MustCompile(`^#?[*a-zA-Z0-9._-]+$`)
)

var tokenNormalizer = strings.NewReplacer("_", "", "-", "", ".", "", ":", "")

type credentials struct {
	issue.MetaData
	pattern          *regexp.Regexp
	entropyThreshold float64
	perCharThreshold float64
	truncate         int
	ignoreEntropy    bool
	minEntropyLength int
}

func truncate(s string, n int) string {
	if n > len(s) {
		return s
	}
	return s[:n]
}

func (r *credentials) isHighEntropyString(str string) bool {
	if len(str) < r.minEntropyLength {
		return false
	}
	s := truncate(str, r.truncate)
	key := entropyCacheKey(s)
	if val, ok := gosec.GlobalCache.Get(key); ok {
		return val.(bool)
	}

	info := zxcvbn.PasswordStrength(s, []string{})
	entropyPerChar := info.Entropy / float64(len(s))
	res := (info.Entropy >= r.entropyThreshold ||
		(info.Entropy >= (r.entropyThreshold/2) &&
			entropyPerChar >= r.perCharThreshold))
	gosec.GlobalCache.Add(key, res)
	return res
}

type secretResult struct {
	ok          bool
	patternName string
}

func (r *credentials) isSecretPattern(str string) (string, bool) {
	if len(str) < r.minEntropyLength {
		return "", false
	}
	key := secretPatternCacheKey(str)
	if res, ok := gosec.GlobalCache.Get(key); ok {
		secretRes := res.(secretResult)
		return secretRes.patternName, secretRes.ok
	}
	for _, pattern := range secretsPatterns {
		if gosec.RegexMatchWithCache(pattern.regexp, str) {
			gosec.GlobalCache.Add(key, secretResult{true, pattern.name})
			return pattern.name, true
		}
	}
	gosec.GlobalCache.Add(key, secretResult{false, ""})
	return "", false
}

// isFalsePositive checks if a value is a false positive (FP), returning true if it is.
// Returns false if the value is a true positive (TP) or unknown.
func (r *credentials) isFalsePositive(valName string, val string) bool {
	// Fail safe for very short and long strings
	if len(val) < 4 || len(val) > 1024 {
		return false
	}

	// Single Pass Analysis
	stats := analyzeToken(val)

	// 0. Constant/EnvVar Reference Convention (Short constants)
	// If the value name indicates it is a safe variable (e.g. env, path, etc), we trust it.
	if stats.length < 64 && stats.hasUpper && !stats.hasSpace && !stats.hasDot && !stats.hasDash && !stats.hasNewline && stats.symbols == 0 {
		if gosec.RegexMatchWithCache(safeNameRegex, valName) && gosec.RegexMatchWithCache(upperCaseConstRegex, val) {
			return true
		}
	}

	// 1. Structural Check: Matched Pairs (Braces, Brackets, Parens)
	// If the value contains matched pairs and valid nesting, or newlines, we treat it as structure.
	if stats.isStructure {
		tokens := tokenRegex.FindAllString(val, -1)
		for _, t := range tokens {
			entropyPerChar, entropyTotal := shannonEntropy(t)
			if entropyTotal > r.entropyThreshold || (entropyPerChar > r.perCharThreshold && entropyTotal > r.entropyThreshold/2) {
				// Strong password signals
				if strings.ContainsAny(t, "!@#$%") {
					return false
				}

				// Check for safe patterns:
				// - Identifiers: reasonably short identifiers, we skip UUIDs (len 36)
				// - Code: PascalCase, camelCase, simple words
				// - URLs/Paths (e.g. within config structures)
				isIdent := isWeakIdentifier(t, nil)
				isCode := gosec.RegexMatchWithCache(codeRegex, t)
				isPath := gosec.RegexMatchWithCache(pathRegex, t)

				if !isIdent && !isCode && !isPath {
					return false // TP: Unknown high-entropy token in structure.
				}
			}
		}
	}

	// 2. Generic Code/Protocol Markers & Identifier/Path Detection
	// Only check these if strict structure is present (no spaces, no newlines)
	if !stats.hasNewline && !stats.hasSpace {
		if strings.HasPrefix(val, "[]") {
			last := val[len(val)-1]
			if last == '(' || last == '{' || last == '[' {
				// High entropy generated code for example []map[string]int{ []pkg.Type{ []*Type{ etc
				return true
			}
		}
		if gosec.RegexMatchWithCache(headerRegex, val) {
			return true
		}

		// URLs (safe if no query params)
		if stats.hasDot && stats.hasSlash && stats.hasColon && gosec.RegexMatchWithCache(safeURLRegex, val) {
			return true
		}
		// Paths
		if stats.hasSlash && gosec.RegexMatchWithCache(pathRegex, val) {
			return true
		}
		// Identifiers (e.g. key-name, config.value, system_var)
		if isWeakIdentifier(val, &stats) {
			return true
		}
		// Strong structural markers (colon, backslash) that are valid identifiers
		// We explicitly exclude URLs (contain "://") to ensure they don't get swallowed as "keys" if they contain secrets.
		if (stats.hasColon || stats.hasBackslash) && !strings.Contains(val, "://") && gosec.RegexMatchWithCache(identifierRegex, val) {
			return true
		}
	}

	// 3. Name Coverage Check - is the name a prefix of the value?
	// If the value is significantly longer (e.g. 2x), it's likely a real secret with a prefix.
	nameLower := strings.ToLower(valName)
	valLower := val
	if stats.hasUpper {
		valLower = strings.ToLower(val)
	}
	if !stats.hasNewline && len(nameLower) >= 4 && len(valLower) >= 4 && len(valLower) < len(nameLower)*2 {
		normName := tokenNormalizer.Replace(nameLower)
		normVal := tokenNormalizer.Replace(valLower)
		if len(normName) >= 4 && len(normVal) >= 4 && len(normVal) < len(normName)*2 {
			lcs := longestCommonSubstring(normName, normVal)
			coverage := float64(lcs) / float64(min(len(normName), len(normVal)))
			if lcs >= 4 && coverage >= 0.8 {
				return true
			}
		}
	}

	// 4. Structure Check (Sentences, SQL)

	// Internationalization / UI Check:
	flength := float64(stats.length)
	var symDensity, digDensity float64
	if flength > 0 {
		symDensity = float64(stats.symbols) / flength
		digDensity = float64(stats.digits) / flength
	}

	// If the string contains non-ASCII letters (e.g., Japanese, Chinese, Accented characters)
	// AND has low symbol/digit density, it is likely a UI string/description.
	// If it has high density (e.g. "Päs5wörd!"), it might be a non-ASCII secret.
	if stats.hasNonASCII {
		if symDensity < 0.1 && digDensity < 0.1 {
			return true
		}
	}

	if stats.hasSpace {
		// Natural Language Check:
		// Sentences in many languages have low symbol density (mostly just punctuation)
		// and relatively low digit density.
		// Strong passphrases usually have high symbol density (> 0.1).
		// Mixed secrets (like Bearer tokens) often have high digit density (> 0.1).
		if symDensity < 0.1 && digDensity < 0.1 {
			return true
		}
		// SQL: Distinguish schema vs data/scripts
		if strings.Contains(valLower, "insert into") || strings.Contains(valLower, "select ") || strings.Contains(valLower, "delete from") || strings.Contains(valLower, "update ") || strings.Contains(valLower, "create table") || strings.Contains(valLower, "upsert into") || strings.Contains(valLower, "set password") || strings.Contains(valLower, "alter user") || strings.Contains(valLower, "identified by") {
			// If it contains data/assignment, it might be a script (TP)
			if stats.hasEqual || strings.Contains(valLower, "values") || strings.Contains(valLower, "identified by") {
				// If it contains placeholders, it's likely a template (FP)
				if gosec.RegexMatchWithCache(sqlPlaceholderRegex, valLower) {
					return true
				}
				return false
			}
			return true
		}
	}

	// Fallback for general structures with no clear secrets
	if stats.isStructure {
		return true
	}

	return false
}

func shannonEntropy(s string) (float64, float64) {
	if s == "" {
		return 0, 0
	}
	// Use a stack-allocated array for ASCII characters to avoid heap allocation
	var asciiCounts [256]int
	var unicodeCounts map[rune]int
	length := 0

	for _, char := range s {
		length++
		if char < 256 {
			asciiCounts[char]++
		} else {
			if unicodeCounts == nil {
				unicodeCounts = make(map[rune]int)
			}
			unicodeCounts[char]++
		}
	}

	entropy := 0.0
	flength := float64(length)

	for _, count := range asciiCounts {
		if count > 0 {
			freq := float64(count) / flength
			entropy -= freq * math.Log2(freq)
		}
	}

	for _, count := range unicodeCounts {
		freq := float64(count) / flength
		entropy -= freq * math.Log2(freq)
	}

	return entropy, entropy * flength
}

func longestCommonSubstring(s1, s2 string) int {
	if len(s1) == 0 || len(s2) == 0 {
		return 0
	}
	if len(s1) < len(s2) {
		s1, s2 = s2, s1
	}
	m, n := len(s1), len(s2)
	curr := make([]int, n+1)
	prev := make([]int, n+1)
	longest := 0
	for i := 1; i <= m; i++ {
		for j := 1; j <= n; j++ {
			if s1[i-1] == s2[j-1] {
				curr[j] = prev[j-1] + 1
				if curr[j] > longest {
					longest = curr[j]
				}
			} else {
				curr[j] = 0
			}
		}
		copy(prev, curr)
	}
	return longest
}

// analyzeToken gathers statistics about a string token, including length,
// character composition (digits, symbols), and structural flags.
// It returns a stringStats struct containing these metrics.
func analyzeToken(s string) stringStats {
	stats := stringStats{}
	if s == "" {
		return stats
	}

	// Structure checking state
	var stack []rune
	balanced := true
	pairCount := 0

	for _, r := range s {
		stats.length++

		// Combined switch: flags + nesting
		switch r {
		case ' ', '\t', '\r':
			stats.hasSpace = true
		case '.':
			stats.hasDot = true
		case '-':
			stats.hasDash = true
		case '_':
			stats.hasUnderscore = true
		case ':':
			stats.hasColon = true
		case '\\':
			stats.hasBackslash = true
		case '/':
			stats.hasSlash = true
		case '\n':
			stats.hasNewline = true
		case '=':
			stats.hasEqual = true

		case '(', '{', '[':
			stack = append(stack, r)

		case ')', '}', ']':
			if len(stack) > 0 {
				prev := stack[len(stack)-1]
				if (prev == '(' && r == ')') ||
					(prev == '{' && r == '}') ||
					(prev == '[' && r == ']') {
					stack = stack[:len(stack)-1]
					pairCount++
				} else {
					balanced = false
				}
			} else {
				balanced = false
			}
		}

		// Density & Classification
		if r < 128 {
			// ASCII fast path - mutually exclusive ranges
			if r >= '0' && r <= '9' {
				stats.digits++
			} else if r >= 'A' && r <= 'Z' {
				stats.hasUpper = true
			} else if r >= 'a' && r <= 'z' {
				// lowercase letter: nothing else needed
			} else if r == ' ' || (r >= '\t' && r <= '\r') {
				// whitespace: nothing else needed
			} else {
				stats.symbols++
			}
		} else {
			// Unicode slow path
			if unicode.IsDigit(r) {
				stats.digits++
			} else if unicode.IsLetter(r) {
				stats.hasNonASCII = true
				if unicode.IsUpper(r) {
					stats.hasUpper = true
				}
			} else if !unicode.IsSpace(r) {
				stats.symbols++
			}
		}
	}

	// Final Structure Determination
	isBalancedStructure := balanced && len(stack) == 0 && pairCount > 0
	stats.isStructure = stats.hasNewline || isBalancedStructure

	return stats
}

// isWeakIdentifier checks if a string resembles a valid weak identifier.
// It matches against weakIdentifierRegex and enforces length limits (shorter
// than UUID for mixed-char tokens, or < 64 for dot-separated tokens)
// and ensures specific separators (. or -_) are present.
// It can optionally use pre-calculated stringStats to avoid re-scanning the string.
func isWeakIdentifier(val string, stats *stringStats) bool {
	if !gosec.RegexMatchWithCache(weakIdentifierRegex, val) {
		return false
	}
	var length int
	var hasDot, hasCommonSep bool

	if stats != nil {
		length = stats.length
		hasDot = stats.hasDot
		hasCommonSep = stats.hasDash || stats.hasUnderscore
	} else {
		length = len(val)
		hasDot = strings.Contains(val, ".")
		hasCommonSep = strings.ContainsAny(val, "-_")
	}

	// Domain/Filename markers (allow longer)
	if hasDot && length < 64 {
		return true
	}
	// General Identifiers (dash, underscore, etc)
	if hasCommonSep && length < uuidLength {
		return true
	}
	return false
}

func (r *credentials) isCredential(valName string, val string) (string, bool) {
	if r.ignoreEntropy || r.isHighEntropyString(val) {
		if patternName, ok := r.isSecretPattern(val); ok {
			return fmt.Sprintf("%s: %s", r.What, patternName), true
		}
		if gosec.RegexMatchWithCache(r.pattern, valName) && !r.isFalsePositive(valName, val) {
			return r.What, true
		}
	}
	return "", false
}

func (r *credentials) Match(n ast.Node, ctx *gosec.Context) (*issue.Issue, error) {
	switch node := n.(type) {
	case *ast.AssignStmt:
		return r.matchAssign(node, ctx)
	case *ast.ValueSpec:
		return r.matchValueSpec(node, ctx)
	case *ast.BinaryExpr:
		return r.matchEqualityCheck(node, ctx)
	case *ast.CompositeLit:
		return r.matchCompositeLit(node, ctx)
	}
	return nil, nil
}

func (r *credentials) matchAssign(assign *ast.AssignStmt, ctx *gosec.Context) (*issue.Issue, error) {
	for _, i := range assign.Lhs {
		if ident, ok := i.(*ast.Ident); ok {
			for _, e := range assign.Rhs {
				if val, err := gosec.GetString(e); err == nil {
					if desc, ok := r.isCredential(ident.Name, val); ok {
						return ctx.NewIssue(assign, r.ID(), desc, r.Severity, r.Confidence), nil
					}
				}
			}
		}
	}
	return nil, nil
}

func (r *credentials) matchValueSpec(valueSpec *ast.ValueSpec, ctx *gosec.Context) (*issue.Issue, error) {
	for index, ident := range valueSpec.Names {
		if valueSpec.Values != nil {
			if len(valueSpec.Values) <= index {
				index = len(valueSpec.Values) - 1
			}
			if val, err := gosec.GetString(valueSpec.Values[index]); err == nil {
				if desc, ok := r.isCredential(ident.Name, val); ok {
					return ctx.NewIssue(valueSpec, r.ID(), desc, r.Severity, r.Confidence), nil
				}
			}
		}
	}

	return nil, nil
}

func (r *credentials) matchEqualityCheck(binaryExpr *ast.BinaryExpr, ctx *gosec.Context) (*issue.Issue, error) {
	if binaryExpr.Op == token.EQL || binaryExpr.Op == token.NEQ {
		ident, ok := binaryExpr.X.(*ast.Ident)
		if !ok {
			ident, _ = binaryExpr.Y.(*ast.Ident)
		}

		var valueNode ast.Node
		if _, ok := binaryExpr.X.(*ast.BasicLit); ok {
			valueNode = binaryExpr.X
		} else if _, ok := binaryExpr.Y.(*ast.BasicLit); ok {
			valueNode = binaryExpr.Y
		}

		if valueNode != nil {
			if val, err := gosec.GetString(valueNode); err == nil {
				varName := ""
				if ident != nil {
					varName = ident.Name
				}
				if desc, ok := r.isCredential(varName, val); ok {
					return ctx.NewIssue(binaryExpr, r.ID(), desc, r.Severity, r.Confidence), nil
				}
			}
		}
	}
	return nil, nil
}

func (r *credentials) matchCompositeLit(lit *ast.CompositeLit, ctx *gosec.Context) (*issue.Issue, error) {
	for _, elt := range lit.Elts {
		if kv, ok := elt.(*ast.KeyValueExpr); ok {
			varName := ""
			if ident, ok := kv.Key.(*ast.Ident); ok {
				varName = ident.Name
			} else if keyStr, err := gosec.GetString(kv.Key); err == nil {
				varName = keyStr
			}

			if val, err := gosec.GetString(kv.Value); err == nil {
				if desc, ok := r.isCredential(varName, val); ok {
					return ctx.NewIssue(lit, r.ID(), desc, r.Severity, r.Confidence), nil
				}
			}
		}
	}
	return nil, nil
}

// NewHardcodedCredentials attempts to find high entropy string constants being
// assigned to variables that appear to be related to credentials.
func NewHardcodedCredentials(id string, conf gosec.Config) (gosec.Rule, []ast.Node) {
	pattern := `(?i)passwd|pass|password|pwd|secret|token|pw|apiKey|bearer|cred`
	entropyThreshold := 80.0
	perCharThreshold := 3.0
	ignoreEntropy := false
	truncateString := 16
	minEntropyLength := 8
	if val, ok := conf[id]; ok {
		conf := val.(map[string]interface{})
		if configPattern, ok := conf["pattern"]; ok {
			if cfgPattern, ok := configPattern.(string); ok {
				pattern = cfgPattern
			}
		}

		if configIgnoreEntropy, ok := conf["ignore_entropy"]; ok {
			if cfgIgnoreEntropy, ok := configIgnoreEntropy.(bool); ok {
				ignoreEntropy = cfgIgnoreEntropy
			}
		}
		if configEntropyThreshold, ok := conf["entropy_threshold"]; ok {
			if cfgEntropyThreshold, ok := configEntropyThreshold.(string); ok {
				if parsedNum, err := strconv.ParseFloat(cfgEntropyThreshold, 64); err == nil {
					entropyThreshold = parsedNum
				}
			}
		}
		if configCharThreshold, ok := conf["per_char_threshold"]; ok {
			if cfgCharThreshold, ok := configCharThreshold.(string); ok {
				if parsedNum, err := strconv.ParseFloat(cfgCharThreshold, 64); err == nil {
					perCharThreshold = parsedNum
				}
			}
		}
		if configTruncate, ok := conf["truncate"]; ok {
			if cfgTruncate, ok := configTruncate.(string); ok {
				if parsedInt, err := strconv.Atoi(cfgTruncate); err == nil {
					truncateString = parsedInt
				}
			}
		}
		if configMinEntropyLength, ok := conf["min_entropy_length"]; ok {
			if cfgMinEntropyLength, ok := configMinEntropyLength.(string); ok {
				if parsedInt, err := strconv.Atoi(cfgMinEntropyLength); err == nil {
					minEntropyLength = parsedInt
				}
			}
		}
	}

	return &credentials{
		pattern:          regexp.MustCompile(pattern),
		entropyThreshold: entropyThreshold,
		perCharThreshold: perCharThreshold,
		ignoreEntropy:    ignoreEntropy,
		truncate:         truncateString,
		minEntropyLength: minEntropyLength,
		MetaData:         issue.NewMetaData(id, "Potential hardcoded credentials", issue.High, issue.Low),
	}, []ast.Node{(*ast.AssignStmt)(nil), (*ast.ValueSpec)(nil), (*ast.BinaryExpr)(nil), (*ast.CompositeLit)(nil)}
}
