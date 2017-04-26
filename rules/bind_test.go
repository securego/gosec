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

	"github.com/GoASTScanner/gas"
)

func TestBind0000(t *testing.T) {
	config := map[string]interface{}{"ignoreNosec": false}
	analyzer := gas.NewAnalyzer(config, nil)
	analyzer.AddRule(NewBindsToAllNetworkInterfaces(config))

	issues := gasTestRunner(`
		package main
	        import (
                	"log"
                	"net"
        	)
		func main() {
			l, err := net.Listen("tcp", "0.0.0.0:2000")
			if err != nil {
				log.Fatal(err)
			}
			defer l.Close()
		}`, analyzer)

	checkTestResults(t, issues, 1, "Binds to all network interfaces")
}

func TestBindEmptyHost(t *testing.T) {
	config := map[string]interface{}{"ignoreNosec": false}
	analyzer := gas.NewAnalyzer(config, nil)
	analyzer.AddRule(NewBindsToAllNetworkInterfaces(config))

	issues := gasTestRunner(`
		package main
	        import (
                	"log"
                	"net"
        	)
		func main() {
                	l, err := net.Listen("tcp", ":2000")
			if err != nil {
				log.Fatal(err)
			}
			defer l.Close()
		}`, analyzer)

	checkTestResults(t, issues, 1, "Binds to all network interfaces")
}
