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
	"testing"

	gas "github.com/GoASTScanner/gas/core"
)

func TestBigExp(t *testing.T) {
	config := map[string]interface{}{"ignoreNosec": false}
	analyzer := gas.NewAnalyzer(config, nil)
	analyzer.AddRule(NewUsingBigExp("TEST", config))

	issues := gasTestRunner(`
        package main

        import (
        	"math/big"
        )

        func main() {
            z := new(big.Int)
            x := new(big.Int)
            x = x.SetUint64(2)
            y := new(big.Int)
            y = y.SetUint64(4)
            m := new(big.Int)
            m = m.SetUint64(0)

            z = z.Exp(x, y, m)
        }
        `, analyzer)

	checkTestResults(t, issues, 1, "Use of math/big.Int.Exp function")
}
