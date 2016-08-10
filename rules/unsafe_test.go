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

	gas "github.com/HewlettPackard/gas/core"
)

func TestUnsafe(t *testing.T) {
	config := map[string]interface{}{"ignoreNosec": false}
	analyzer := gas.NewAnalyzer(config, nil)
	analyzer.AddRule(NewUsingUnsafe(config))

	issues := gasTestRunner(`
        package main

        import (
        	"fmt"
        	"unsafe"
        )

        func main() {
        	intArray := [...]int{1, 2}
        	fmt.Printf("\nintArray: %v\n", intArray)
        	intPtr := &intArray[0]
        	fmt.Printf("\nintPtr=%p, *intPtr=%d.\n", intPtr, *intPtr)
        	addressHolder := uintptr(unsafe.Pointer(intPtr)) + unsafe.Sizeof(intArray[0])
        	intPtr = (*int)(unsafe.Pointer(addressHolder))
        	fmt.Printf("\nintPtr=%p, *intPtr=%d.\n\n", intPtr, *intPtr)
        }
        `, analyzer)

	checkTestResults(t, issues, 3, "Use of unsafe calls")

}
