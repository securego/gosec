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

package main

import (
	"go/ast"

	gas "github.com/GoASTScanner/gas/core"
	"github.com/GoASTScanner/gas/rules"
)

type RuleInfo struct {
	id          string
	description string
	build       func(string, map[string]interface{}) (gas.Rule, []ast.Node)
}

// GetFullRuleList get the full list of all rules available to GAS
func GetFullRuleList() map[string]RuleInfo {
	rules := []RuleInfo{
		// misc
		RuleInfo{"G101", "Look for hardcoded credentials", rules.NewHardcodedCredentials},
		RuleInfo{"G102", "Bind to all interfaces", rules.NewBindsToAllNetworkInterfaces},
		RuleInfo{"G103", "Audit the use of unsafe block", rules.NewUsingUnsafe},
		RuleInfo{"G104", "Audit errors not checked", rules.NewNoErrorCheck},
		RuleInfo{"G105", "Audit the use of big.Exp function", rules.NewUsingBigExp},

		// injection
		RuleInfo{"G201", "SQL query construction using format string", rules.NewSqlStrFormat},
		RuleInfo{"G202", "SQL query construction using string concatenation", rules.NewSqlStrConcat},
		RuleInfo{"G203", "Use of unescaped data in HTML templates", rules.NewTemplateCheck},
		RuleInfo{"G204", "Audit use of command execution", rules.NewSubproc},

		// filesystem
		RuleInfo{"G301", "Poor file permissions used when creating a directory", rules.NewMkdirPerms},
		RuleInfo{"G302", "Poor file permisions used when creation file or using chmod", rules.NewFilePerms},
		RuleInfo{"G303", "Creating tempfile using a predictable path", rules.NewBadTempFile},

		// crypto
		RuleInfo{"G401", "Detect the usage of DES, RC4, or MD5", rules.NewUsesWeakCryptography},
		RuleInfo{"G402", "Look for bad TLS connection settings", rules.NewIntermediateTlsCheck},
		RuleInfo{"G403", "Ensure minimum RSA key length of 2048 bits", rules.NewWeakKeyStrength},
		RuleInfo{"G404", "Insecure random number source (rand)", rules.NewWeakRandCheck},

		// blacklist
		RuleInfo{"G501", "Import blacklist: crypto/md5", rules.NewBlacklist_crypto_md5},
		RuleInfo{"G502", "Import blacklist: crypto/des", rules.NewBlacklist_crypto_des},
		RuleInfo{"G503", "Import blacklist: crypto/rc4", rules.NewBlacklist_crypto_rc4},
		RuleInfo{"G504", "Import blacklist: net/http/cgi", rules.NewBlacklist_net_http_cgi},
	}
	ruleMap := make(map[string]RuleInfo)
	for _, v := range rules {
		ruleMap[v.id] = v
	}
	return ruleMap
}

func AddRules(analyzer *gas.Analyzer, conf map[string]interface{}) {
	var all map[string]RuleInfo

	inc := conf["include"].([]string)
	exc := conf["exclude"].([]string)

	// add included rules
	if len(inc) == 0 {
		all = GetFullRuleList()
	} else {
		all = map[string]RuleInfo{}
		tmp := GetFullRuleList()
		for _, v := range inc {
			if val, ok := tmp[v]; ok {
				all[v] = val
			}
		}
	}

	// remove excluded rules
	for _, v := range exc {
		delete(all, v)
	}

	for k, v := range all {
		analyzer.AddRule(v.build(k, conf))
	}
}
