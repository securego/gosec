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
	"strings"

	gas "github.com/HewlettPackard/gas/core"
	"github.com/HewlettPackard/gas/rules"
)

type ruleMaker func() (gas.Rule, ast.Node)
type ruleConfig struct {
	enabled      bool
	constructors []ruleMaker
}

type rulelist struct {
	rules       map[string]*ruleConfig
	overwritten bool
}

func newRulelist() rulelist {
	var rs rulelist
	rs.rules = make(map[string]*ruleConfig)
	rs.overwritten = false
	rs.register("sql", rules.NewSqlStrConcat, rules.NewSqlStrFormat)
	rs.register("crypto", rules.NewImportsWeakCryptography, rules.NewUsesWeakCryptography)
	rs.register("hardcoded", rules.NewHardcodedCredentials)
	rs.register("perms", rules.NewMkdirPerms, rules.NewChmodPerms)
	rs.register("tempfile", rules.NewBadTempFile)
	rs.register("tls_good", rules.NewModernTlsCheck)
	rs.register("tls_ok", rules.NewIntermediateTlsCheck)
	rs.register("tls_old", rules.NewCompatTlsCheck)
	rs.register("bind", rules.NewBindsToAllNetworkInterfaces)
	rs.register("unsafe", rules.NewUsingUnsafe)
	rs.register("rsa", rules.NewWeakKeyStrength)
	rs.register("templates", rules.NewTemplateCheck)
	rs.register("exec", rules.NewSubproc)
	rs.register("errors", rules.NewNoErrorCheck)
	rs.register("httpoxy", rules.NewHttpoxyTest)
	return rs
}

func (r *rulelist) register(name string, cons ...ruleMaker) {
	r.rules[name] = &ruleConfig{false, cons}
}

func (r *rulelist) useDefaults() {
	for k := range r.rules {
		r.rules[k].enabled = true
	}
}

func (r *rulelist) list() []string {
	i := 0
	keys := make([]string, len(r.rules))
	for k := range r.rules {
		keys[i] = k
		i++
	}
	return keys
}

func (r *rulelist) apply(g *gas.Analyzer) {
	for _, v := range r.rules {
		if v.enabled {
			for _, ctor := range v.constructors {
				g.AddRule(ctor())
			}
		}
	}
}

func (r *rulelist) String() string {
	return strings.Join(r.list(), ", ")
}

func (r *rulelist) Set(opt string) error {
	r.overwritten = true
	if x, ok := r.rules[opt]; ok {
		x.enabled = true
		return nil
	}
	return fmt.Errorf("Valid rules are: %s", r)
}
