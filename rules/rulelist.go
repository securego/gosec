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
	"github.com/GoASTScanner/gas"
)

// RuleDefinition contains the description of a rule and a mechanism to
// create it.
type RuleDefinition struct {
	ID          string
	Description string
	Create      gas.RuleBuilder
}

// RuleList is a mapping of rule ID's to rule definitions
type RuleList map[string]RuleDefinition

// Builders returns all the create methods for a given rule list
func (rl RuleList) Builders() map[string]gas.RuleBuilder {
	builders := make(map[string]gas.RuleBuilder)
	for _, def := range rl {
		builders[def.ID] = def.Create
	}
	return builders
}

// RuleFilter can be used to include or exclude a rule depending on the return
// value of the function
type RuleFilter func(string) bool

// NewRuleFilter is a closure that will include/exclude the rule ID's based on
// the supplied boolean value.
func NewRuleFilter(action bool, ruleIDs ...string) RuleFilter {
	rulelist := make(map[string]bool)
	for _, rule := range ruleIDs {
		rulelist[rule] = true
	}
	return func(rule string) bool {
		if _, found := rulelist[rule]; found {
			return action
		}
		return !action
	}
}

// Generate the list of rules to use
func Generate(filters ...RuleFilter) RuleList {
	rules := []RuleDefinition{
		// misc
		RuleDefinition{"G101", "Look for hardcoded credentials", NewHardcodedCredentials},
		RuleDefinition{"G102", "Bind to all interfaces", NewBindsToAllNetworkInterfaces},
		RuleDefinition{"G103", "Audit the use of unsafe block", NewUsingUnsafe},
		RuleDefinition{"G104", "Audit errors not checked", NewNoErrorCheck},
		RuleDefinition{"G105", "Audit the use of big.Exp function", NewUsingBigExp},
		RuleDefinition{"G106", "Audit the use of ssh.InsecureIgnoreHostKey function", NewSSHHostKey},

		// injection
		RuleDefinition{"G201", "SQL query construction using format string", NewSQLStrFormat},
		RuleDefinition{"G202", "SQL query construction using string concatenation", NewSQLStrConcat},
		RuleDefinition{"G203", "Use of unescaped data in HTML templates", NewTemplateCheck},
		RuleDefinition{"G204", "Audit use of command execution", NewSubproc},

		// filesystem
		RuleDefinition{"G301", "Poor file permissions used when creating a directory", NewMkdirPerms},
		RuleDefinition{"G302", "Poor file permisions used when creation file or using chmod", NewFilePerms},
		RuleDefinition{"G303", "Creating tempfile using a predictable path", NewBadTempFile},

		// crypto
		RuleDefinition{"G401", "Detect the usage of DES, RC4, or MD5", NewUsesWeakCryptography},
		RuleDefinition{"G402", "Look for bad TLS connection settings", NewIntermediateTLSCheck},
		RuleDefinition{"G403", "Ensure minimum RSA key length of 2048 bits", NewWeakKeyStrength},
		RuleDefinition{"G404", "Insecure random number source (rand)", NewWeakRandCheck},

		// blacklist
		RuleDefinition{"G501", "Import blacklist: crypto/md5", NewBlacklistedImportMD5},
		RuleDefinition{"G502", "Import blacklist: crypto/des", NewBlacklistedImportDES},
		RuleDefinition{"G503", "Import blacklist: crypto/rc4", NewBlacklistedImportRC4},
		RuleDefinition{"G504", "Import blacklist: net/http/cgi", NewBlacklistedImportCGI},
	}

	ruleMap := make(map[string]RuleDefinition)

RULES:
	for _, rule := range rules {
		for _, filter := range filters {
			if filter(rule.ID) {
				continue RULES
			}
		}
		ruleMap[rule.ID] = rule
	}
	return ruleMap
}
