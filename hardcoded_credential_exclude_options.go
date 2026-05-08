package gosec

import (
	"errors"
	"fmt"
	"regexp"
)

// HardcodedCredentialExcludeOptions configures whether
// a Hardcoded Credentials issue should be excluded
// from the results, based on options specific to this rule.
type HardcodedCredentialExcludeOptions struct {
	// Keys holds a list of Go regexp patterns.
	// If on a Hardcoded Credentials issue any pattern matches
	// a map key, a const, var, or struct field name,
	// the issue will be excluded from the report.
	// If empty, we behave as if no exclude key pattern matched.
	Keys []string `json:"keys"`

	// Keys holds a list of Go regexp patterns.
	// If on a Hardcoded Credentials issue any pattern matches a hardcoded value,
	// the issue will be excluded from the report.
	// If empty, we behave as if no exclude value pattern matched.
	Values []string `json:"values"`
}

type CompiledHardcodedCredentialsRule struct {
	// anyExcludes indicates whether any regexp patterns
	// for Keys or Values have been set.
	anyExcludes bool

	// keys holds compiled Go regexp patterns
	// of map keys, or const, var or struct field names to exclude.
	keys []*regexp.Regexp

	// values holds compiled Go regexp patterns of hardcoded values to exclude.
	values []*regexp.Regexp
}

// CompileRegexes compiles a slice of regex patterns.
// Returns nil if an empty patterns slice is provided.
// Returns an error if any pattern is empty or failed to compile.
func CompileRegexes(patterns []string) ([]*regexp.Regexp, []error) {
	if len(patterns) == 0 {
		return nil, nil
	}

	regexes := make([]*regexp.Regexp, len(patterns))
	var errs []error
	for i, pattern := range patterns {
		if pattern == "" {
			err := fmt.Errorf("[%d]: must not be empty", i)
			errs = append(errs, err)
			continue
		}
		regex, err := regexp.Compile(pattern)
		if err != nil {
			err := fmt.Errorf("[%d]: %q: %w", i, pattern, err)
			errs = append(errs, err)
			continue
		}
		regexes[i] = regex
	}

	if len(errs) > 0 {
		return nil, errs
	}
	return regexes, nil
}

// AnyRegexMatch returns whether any of the regexps match s.
func AnyRegexMatch(s string, regexps []*regexp.Regexp) bool {
	for _, re := range regexps {
		if RegexMatchWithCache(re, s) {
			return true
		}
	}
	return false
}

// Compile converts the receiver into a CompiledHardcodedCredentialsRule.
func (o HardcodedCredentialExcludeOptions) Compile() (*CompiledHardcodedCredentialsRule, error) {
	var allErrs []error

	// Compile the keys.
	keys, errs := CompileRegexes(o.Keys)
	for _, err := range errs {
		allErrs = append(allErrs, fmt.Errorf("keys%w", err))
	}

	// Compile the values.
	values, errs := CompileRegexes(o.Values)
	for _, err := range errs {
		allErrs = append(allErrs, fmt.Errorf("values%w", err))
	}

	// Check for errors.
	if len(allErrs) > 0 {
		return nil, fmt.Errorf(
			"failed to compile exclude options: %w",
			errors.Join(allErrs...),
		)
	}

	return &CompiledHardcodedCredentialsRule{
		anyExcludes: len(keys)+len(values) > 0,
		keys:        keys,
		values:      values,
	}, nil
}

// AnyExcludes returns whether any exclude keys or values have been configured.
func (r *CompiledHardcodedCredentialsRule) AnyExcludes() bool {
	return r == nil || r.anyExcludes
}

// ShouldExcludeKV returns whether key or value should be excluded
// from the report.
func (r *CompiledHardcodedCredentialsRule) ShouldExcludeKV(key, value string) bool {
	if !r.AnyExcludes() {
		return false
	}
	return AnyRegexMatch(key, r.keys) || AnyRegexMatch(value, r.values)
}
