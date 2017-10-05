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

func TestInsecureSkipVerify(t *testing.T) {
	config := map[string]interface{}{"ignoreNosec": false}
	analyzer := gas.NewAnalyzer(config, nil)
	analyzer.AddRule(NewModernTlsCheck("TEST", config))

	issues := gasTestRunner(`
        package main

        import (
        	"crypto/tls"
        	"fmt"
        	"net/http"
        )

        func main() {
        	tr := &http.Transport{
        		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
        	}
        	client := &http.Client{Transport: tr}
        	_, err := client.Get("https://golang.org/")
        	if err != nil {
        		fmt.Println(err)
        	}
        }
        `, analyzer)

	checkTestResults(t, issues, 1, "TLS InsecureSkipVerify set true")
}

func TestInsecureMinVersion(t *testing.T) {
	config := map[string]interface{}{"ignoreNosec": false}
	analyzer := gas.NewAnalyzer(config, nil)
	analyzer.AddRule(NewModernTlsCheck("TEST", config))

	issues := gasTestRunner(`
        package main

        import (
        	"crypto/tls"
        	"fmt"
        	"net/http"
        )

        func main() {
        	tr := &http.Transport{
        		TLSClientConfig: &tls.Config{MinVersion: 0},
        	}
        	client := &http.Client{Transport: tr}
        	_, err := client.Get("https://golang.org/")
        	if err != nil {
        		fmt.Println(err)
        	}
        }
        `, analyzer)

	checkTestResults(t, issues, 1, "TLS MinVersion too low")
}

func TestInsecureMaxVersion(t *testing.T) {
	config := map[string]interface{}{"ignoreNosec": false}
	analyzer := gas.NewAnalyzer(config, nil)
	analyzer.AddRule(NewModernTlsCheck("TEST", config))

	issues := gasTestRunner(`
        package main

        import (
        	"crypto/tls"
        	"fmt"
        	"net/http"
        )

        func main() {
        	tr := &http.Transport{
        		TLSClientConfig: &tls.Config{MaxVersion: 0},
        	}
        	client := &http.Client{Transport: tr}
        	_, err := client.Get("https://golang.org/")
        	if err != nil {
        		fmt.Println(err)
        	}
        }
        `, analyzer)

	checkTestResults(t, issues, 1, "TLS MaxVersion too low")
}

func TestInsecureCipherSuite(t *testing.T) {
	config := map[string]interface{}{"ignoreNosec": false}
	analyzer := gas.NewAnalyzer(config, nil)
	analyzer.AddRule(NewModernTlsCheck("TEST", config))

	issues := gasTestRunner(`
        package main

        import (
        	"crypto/tls"
        	"fmt"
        	"net/http"
        )

        func main() {
        	tr := &http.Transport{
        		TLSClientConfig: &tls.Config{CipherSuites: []uint16{
                                tls.TLS_RSA_WITH_RC4_128_SHA,
                                tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
                                },},
        	}
        	client := &http.Client{Transport: tr}
        	_, err := client.Get("https://golang.org/")
        	if err != nil {
        		fmt.Println(err)
        	}
        }
        `, analyzer)

	checkTestResults(t, issues, 1, "TLS Bad Cipher Suite: TLS_RSA_WITH_RC4_128_SHA")
}

func TestPreferServerCipherSuites(t *testing.T) {
	config := map[string]interface{}{"ignoreNosec": false}
	analyzer := gas.NewAnalyzer(config, nil)
	analyzer.AddRule(NewModernTlsCheck("TEST", config))

	issues := gasTestRunner(`
        package main

        import (
        	"crypto/tls"
        	"fmt"
        	"net/http"
        )

        func main() {
        	tr := &http.Transport{
        		TLSClientConfig: &tls.Config{PreferServerCipherSuites: false},
        	}
        	client := &http.Client{Transport: tr}
        	_, err := client.Get("https://golang.org/")
        	if err != nil {
        		fmt.Println(err)
        	}
        }
        `, analyzer)

	checkTestResults(t, issues, 1, "TLS PreferServerCipherSuites set false")
}
