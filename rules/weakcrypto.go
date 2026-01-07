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

	"github.com/securego/gosec/v2"
	"github.com/securego/gosec/v2/issue"
)

type weakCryptoUsage struct {
	callListRule
}

// NewUsesWeakCryptographyHash detects uses of md5.*, sha1.* (G401)
func NewUsesWeakCryptographyHash(id string, _ gosec.Config) (gosec.Rule, []ast.Node) {
	calls := gosec.NewCallList()
	calls.AddAll("crypto/md5", "New", "Sum")
	calls.AddAll("crypto/sha1", "New", "Sum")

	return &weakCryptoUsage{callListRule{
		MetaData: issue.MetaData{
			RuleID:     id,
			Severity:   issue.Medium,
			Confidence: issue.High,
			What:       "Use of weak cryptographic primitive",
		},
		calls: calls,
	}}, []ast.Node{(*ast.CallExpr)(nil)}
}

// NewUsesWeakCryptographyEncryption detects uses of des.*, rc4.* (G405)
func NewUsesWeakCryptographyEncryption(id string, _ gosec.Config) (gosec.Rule, []ast.Node) {
	calls := gosec.NewCallList()
	calls.AddAll("crypto/des", "NewCipher", "NewTripleDESCipher")
	calls.Add("crypto/rc4", "NewCipher")

	return &weakCryptoUsage{callListRule{
		MetaData: issue.MetaData{
			RuleID:     id,
			Severity:   issue.Medium,
			Confidence: issue.High,
			What:       "Use of weak cryptographic primitive",
		},
		calls: calls,
	}}, []ast.Node{(*ast.CallExpr)(nil)}
}

// NewUsesWeakDeprecatedCryptographyHash detects uses of md4.New, ripemd160.New (G406)
func NewUsesWeakDeprecatedCryptographyHash(id string, _ gosec.Config) (gosec.Rule, []ast.Node) {
	calls := gosec.NewCallList()
	calls.Add("golang.org/x/crypto/md4", "New")
	calls.Add("golang.org/x/crypto/ripemd160", "New")

	return &weakCryptoUsage{callListRule{
		MetaData: issue.MetaData{
			RuleID:     id,
			Severity:   issue.Medium,
			Confidence: issue.High,
			What:       "Use of deprecated weak cryptographic primitive",
		},
		calls: calls,
	}}, []ast.Node{(*ast.CallExpr)(nil)}
}
