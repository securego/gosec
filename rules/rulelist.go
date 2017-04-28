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
	"go/ast"

	"github.com/GoASTScanner/gas"
)

type RuleDefinition struct {
	Description string
	Create      func(c gas.Config) (gas.Rule, []ast.Node)
}

type RuleList map[string]RuleDefinition

type RuleFilter func(string) bool

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
	rules := map[string]RuleDefinition{
		// misc
		"G101": RuleDefinition{"Look for hardcoded credentials", NewHardcodedCredentials},
		"G102": RuleDefinition{"Bind to all interfaces", NewBindsToAllNetworkInterfaces},
		"G103": RuleDefinition{"Audit the use of unsafe block", NewUsingUnsafe},
		"G104": RuleDefinition{"Audit errors not checked", NewNoErrorCheck},
		"G105": RuleDefinition{"Audit the use of big.Exp function", NewUsingBigExp},

		// injection
		"G201": RuleDefinition{"SQL query construction using format string", NewSqlStrFormat},
		"G202": RuleDefinition{"SQL query construction using string concatenation", NewSqlStrConcat},
		"G203": RuleDefinition{"Use of unescaped data in HTML templates", NewTemplateCheck},
		"G204": RuleDefinition{"Audit use of command execution", NewSubproc},

		// filesystem
		"G301": RuleDefinition{"Poor file permissions used when creating a directory", NewMkdirPerms},
		"G302": RuleDefinition{"Poor file permisions used when creation file or using chmod", NewFilePerms},
		"G303": RuleDefinition{"Creating tempfile using a predictable path", NewBadTempFile},

		// crypto
		"G401": RuleDefinition{"Detect the usage of DES, RC4, or MD5", NewUsesWeakCryptography},
		"G402": RuleDefinition{"Look for bad TLS connection settings", NewIntermediateTlsCheck},
		"G403": RuleDefinition{"Ensure minimum RSA key length of 2048 bits", NewWeakKeyStrength},
		"G404": RuleDefinition{"Insecure random number source (rand)", NewWeakRandCheck},

		// blacklist
		"G501": RuleDefinition{"Import blacklist: crypto/md5", NewBlacklist_crypto_md5},
		"G502": RuleDefinition{"Import blacklist: crypto/des", NewBlacklist_crypto_des},
		"G503": RuleDefinition{"Import blacklist: crypto/rc4", NewBlacklist_crypto_rc4},
		"G504": RuleDefinition{"Import blacklist: net/http/cgi", NewBlacklist_net_http_cgi},
	}

	for rule := range rules {
		for _, filter := range filters {
			if filter(rule) {
				delete(rules, rule)
			}
		}
	}
	return rules
}
