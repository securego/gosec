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
	description string
	build       func(map[string]interface{}) (gas.Rule, []ast.Node)
}

// GetFullRuleList get the full list of all rules available to GAS
func GetFullRuleList() map[string]RuleInfo {
	return map[string]RuleInfo{
		// misc
		"G101": RuleInfo{"Look for hardcoded credentials", rules.NewHardcodedCredentials},
		"G102": RuleInfo{"Bind to all interfaces", rules.NewBindsToAllNetworkInterfaces},
		"G103": RuleInfo{"Audit the use of unsafe block", rules.NewUsingUnsafe},
		"G104": RuleInfo{"Audit errors not checked", rules.NewNoErrorCheck},

		// injection
		"G201": RuleInfo{"SQL query construction using format string", rules.NewSqlStrFormat},
		"G202": RuleInfo{"SQL query construction using string concatenation", rules.NewSqlStrConcat},
		"G203": RuleInfo{"Use of unescaped data in HTML templates", rules.NewTemplateCheck},
		"G204": RuleInfo{"Audit use of command execution", rules.NewSubproc},

		// filesystem
		"G301": RuleInfo{"Poor file permissions used when creating a directory", rules.NewMkdirPerms},
		"G302": RuleInfo{"Poor file permisions used when creation file or using chmod", rules.NewFilePerms},
		"G303": RuleInfo{"Creating tempfile using a predictable path", rules.NewBadTempFile},

		// crypto
		"G401": RuleInfo{"Detect the usage of DES, RC4, or MD5", rules.NewUsesWeakCryptography},
		"G402": RuleInfo{"Look for bad TLS connection settings", rules.NewIntermediateTlsCheck},
		"G403": RuleInfo{"Ensure minimum RSA key length of 2048 bits", rules.NewWeakKeyStrength},
		"G404": RuleInfo{"Insecure random number source (rand)", rules.NewWeakRandCheck},

		// blacklist
		"G501": RuleInfo{"Import blacklist: crypto/md5", rules.NewBlacklist_crypto_md5},
		"G502": RuleInfo{"Import blacklist: crypto/des", rules.NewBlacklist_crypto_des},
		"G503": RuleInfo{"Import blacklist: crypto/rc4", rules.NewBlacklist_crypto_rc4},
		"G504": RuleInfo{"Import blacklist: net/http/cgi", rules.NewBlacklist_net_http_cgi},
	}
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

	for _, v := range all {
		analyzer.AddRule(v.build(conf))
	}
}
