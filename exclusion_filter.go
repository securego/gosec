package gosec

import (
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/securego/gosec/v2/issue"
)

// ExcludeRule defines rules to exclude for specific file paths
type ExcludeRule struct {
	Path   string   `json:"path"`   // Regex pattern for matching file paths
	Keys   []string `json:"keys"`   // Regex patterns for matching keys
	Values []string `json:"values"` // Regex patterns for matching values
	Rules  []string `json:"rules"`  // Rule IDs to exclude. Use "*" to exclude all rules
}

// compiledExcludeRule is a pre-compiled version of PathExcludeRule for efficient matching
type compiledExcludeRule struct {
	pathRegex    *regexp.Regexp
	keyRegexes   []*regexp.Regexp
	valueRegexes []*regexp.Regexp
	ruleSet      map[string]bool // Set of rule IDs to exclude
	excludeAll   bool            // True if "*" was specified in rules
	original     ExcludeRule     // Keep original for error messages
}

// ExclusionFilter handles filtering of issues based on path and rule combinations
type ExclusionFilter struct {
	rules []compiledExcludeRule
}

type (
	Keyer  interface{ Key() string }
	Valuer interface{ Value() string }
)

// CompileRegexes returns a slice of compiled regular expressions.
// Returns nil if an empty patterns slice is provided.
// Returns an error if any pattern is empty or failed to compile.
func CompileRegexes(patterns []string) ([]*regexp.Regexp, error) {
	if len(patterns) == 0 {
		return nil, nil
	}

	regexes := make([]*regexp.Regexp, len(patterns))
	var errs []error
	for i, pattern := range patterns {
		if pattern == "" {
			err := fmt.Errorf("index %d: %q: must not be empty", i, pattern)
			errs = append(errs, err)
			continue
		}
		regex, err := regexp.Compile(pattern)
		if err != nil {
			err := fmt.Errorf("index %d: %q: %w", i, pattern, err)
			errs = append(errs, err)
			continue
		}
		regexes[i] = regex
	}

	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}
	return regexes, nil
}

// NewExclusionFilter creates a new filter from the provided exclusion rules.
// Returns an error if any path regex is invalid.
func NewExclusionFilter(rules []ExcludeRule) (*ExclusionFilter, error) {
	if len(rules) == 0 {
		return &ExclusionFilter{rules: nil}, nil
	}

	compiled := make([]compiledExcludeRule, 0, len(rules))

	for i, rule := range rules {
		if rule.Path == "" {
			return nil, fmt.Errorf("exclude-rules[%d]: path cannot be empty", i)
		}

		regex, err := regexp.Compile(rule.Path)
		if err != nil {
			return nil, fmt.Errorf("exclude-rules[%d]: invalid path regex %q: %w", i, rule.Path, err)
		}

		keyRegexes, err := CompileRegexes(rule.Keys)
		if err != nil {
			return nil, fmt.Errorf("exclude-rules[%d].keys: %w", i, err)
		}

		valueRegexes, err := CompileRegexes(rule.Values)
		if err != nil {
			return nil, fmt.Errorf("exclude-rules[%d].values: %w", i, err)
		}

		ruleSet := make(map[string]bool)
		excludeAll := false

		for _, ruleID := range rule.Rules {
			ruleID = strings.TrimSpace(ruleID)
			if ruleID == "*" {
				excludeAll = true
			} else if ruleID != "" {
				ruleSet[ruleID] = true
			}
		}

		compiled = append(compiled, compiledExcludeRule{
			pathRegex:    regex,
			keyRegexes:   keyRegexes,
			valueRegexes: valueRegexes,
			ruleSet:      ruleSet,
			excludeAll:   excludeAll,
			original:     rule,
		})
	}

	return &ExclusionFilter{rules: compiled}, nil
}

// ShouldExclude returns true if the given issue should be excluded based on
// its file path, rule ID, and addenda
func (f *ExclusionFilter) ShouldExclude(filePath, ruleID string, addenda any) bool {
	if f == nil || len(f.rules) == 0 {
		return false
	}

	// Normalize path separators for consistent matching
	normalizedPath := strings.ReplaceAll(filePath, "\\", "/")

	for _, rule := range f.rules {
		if rule.pathRegex.MatchString(normalizedPath) {
			if rule.excludeAll {
				return true
			}
			if rule.ruleSet[ruleID] {
				return true
			}
		}
	}

	return false
}

// FilterIssues applies path-based exclusions to a slice of issues.
// Returns the filtered issues and the count of excluded issues.
func (f *ExclusionFilter) FilterIssues(issues []*issue.Issue) ([]*issue.Issue, int) {
	if f == nil || len(f.rules) == 0 || len(issues) == 0 {
		return issues, 0
	}

	filtered := make([]*issue.Issue, 0, len(issues))
	excluded := 0

	for _, iss := range issues {
		if f.ShouldExclude(iss.File, iss.RuleID, iss.Addenda) {
			excluded++
			continue
		}
		filtered = append(filtered, iss)
	}

	return filtered, excluded
}

// ParseCLIExcludeRules parses the CLI format for exclude-rules.
// Format: "path:rule1,rule2;path2:rule3,rule4"
// Example: "cmd/.*:G204,G304;test/.*:G101"
func ParseCLIExcludeRules(input string) ([]ExcludeRule, error) {
	if input == "" {
		return nil, nil
	}

	var rules []ExcludeRule

	// Split by semicolon for multiple rules
	parts := strings.Split(input, ";")

	for i, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		// Split by colon to separate path and rules
		colonIdx := strings.LastIndex(part, ":")
		if colonIdx == -1 {
			return nil, fmt.Errorf("exclude-rules part %d: missing ':' separator in %q", i+1, part)
		}

		pathPattern := strings.TrimSpace(part[:colonIdx])
		rulesPart := strings.TrimSpace(part[colonIdx+1:])

		if pathPattern == "" {
			return nil, fmt.Errorf("exclude-rules part %d: path pattern cannot be empty", i+1)
		}

		if rulesPart == "" {
			return nil, fmt.Errorf("exclude-rules part %d: rules list cannot be empty", i+1)
		}

		// Split rules by comma
		ruleIDs := strings.Split(rulesPart, ",")
		cleanedRules := make([]string, 0, len(ruleIDs))
		for _, r := range ruleIDs {
			r = strings.TrimSpace(r)
			if r != "" {
				cleanedRules = append(cleanedRules, r)
			}
		}

		if len(cleanedRules) == 0 {
			return nil, fmt.Errorf("exclude-rules part %d: no valid rules specified", i+1)
		}

		rules = append(rules, ExcludeRule{
			Path:  pathPattern,
			Rules: cleanedRules,
		})
	}

	return rules, nil
}

// MergeExcludeRules combines exclude rules from multiple sources (config file + CLI).
// CLI rules take precedence and are processed first.
func MergeExcludeRules(configRules, cliRules []ExcludeRule) []ExcludeRule {
	if len(cliRules) == 0 {
		return configRules
	}
	if len(configRules) == 0 {
		return cliRules
	}

	// CLI rules first, then config rules
	merged := make([]ExcludeRule, 0, len(cliRules)+len(configRules))
	merged = append(merged, cliRules...)
	merged = append(merged, configRules...)
	return merged
}

// String returns a human-readable representation of the filter
func (f *ExclusionFilter) String() string {
	if f == nil || len(f.rules) == 0 {
		return "ExclusionFilter{empty}"
	}

	var parts []string
	for _, rule := range f.rules {
		if rule.excludeAll {
			parts = append(parts, fmt.Sprintf("%s:*", rule.original.Path))
		} else {
			ruleIDs := make([]string, 0, len(rule.ruleSet))
			for id := range rule.ruleSet {
				ruleIDs = append(ruleIDs, id)
			}
			parts = append(parts, fmt.Sprintf("%s:[%s]", rule.original.Path, strings.Join(ruleIDs, ",")))
		}
	}

	return fmt.Sprintf("ExclusionFilter{%s}", strings.Join(parts, "; "))
}
