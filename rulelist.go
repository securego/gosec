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
	"fmt"
	"go/ast"

	gas "github.com/HewlettPackard/gas/core"
	"github.com/HewlettPackard/gas/rules"
)

type RuleInfo struct {
	description string
	build       func(map[string]interface{}) (gas.Rule, ast.Node)
}

// GetFullRuleList get the full list of all rules available to GAS
func GetFullRuleList() map[string]RuleInfo {
	return map[string]RuleInfo{
		// misc
		"G101": RuleInfo{"hardcoded credentials", rules.NewHardcodedCredentials},
		"G102": RuleInfo{"bind to all interfaces", rules.NewBindsToAllNetworkInterfaces},
		"G103": RuleInfo{"use of unsafe block", rules.NewUsingUnsafe},
		"G104": RuleInfo{"errors not checked", rules.NewTemplateCheck},

		// injection
		"G201": RuleInfo{"sql string format", rules.NewSqlStrFormat},
		"G202": RuleInfo{"sql string concat", rules.NewSqlStrConcat},
		"G203": RuleInfo{"unescaped templates", rules.NewTemplateCheck},
		"G204": RuleInfo{"use of exec", rules.NewSubproc},

		// filesystem
		"G301": RuleInfo{"poor mkdir permissions", rules.NewMkdirPerms},
		"G302": RuleInfo{"poor chmod permisions", rules.NewChmodPerms},
		"G303": RuleInfo{"predicatable tempfile", rules.NewBadTempFile},

		// crypto
		"G401": RuleInfo{"weak crypto", rules.NewUsesWeakCryptography},
		"G402": RuleInfo{"bad TLS options", rules.NewIntermediateTlsCheck},
		"G403": RuleInfo{"bad RSA key length", rules.NewWeakKeyStrength},
		"G404": RuleInfo{"poor random source (rand)", rules.NewWeakRandCheck},

		// blacklist
		"G501": RuleInfo{"blacklist: crypto/md5", rules.NewBlacklist_crypto_md5},
		"G502": RuleInfo{"blacklist: crypto/des", rules.NewBlacklist_crypto_des},
		"G503": RuleInfo{"blacklist: crypto/rc4", rules.NewBlacklist_crypto_rc4},
		"G504": RuleInfo{"blacklist: net/http/cgi", rules.NewBlacklist_net_http_cgi},
	}
}

func AddRules(analyzer *gas.Analyzer, conf map[string]interface{}) {
	var all map[string]RuleInfo

	inc := conf["include"].([]string)
	exc := conf["exclude"].([]string)

	fmt.Println(len(inc))

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
