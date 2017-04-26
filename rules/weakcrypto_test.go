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

func TestMD5(t *testing.T) {
	config := map[string]interface{}{"ignoreNosec": false}
	analyzer := gas.NewAnalyzer(config, nil)
	analyzer.AddRule(NewBlacklist_crypto_md5(config))
	analyzer.AddRule(NewUsesWeakCryptography(config))

	issues := gasTestRunner(`
                package main
                import (
                	"crypto/md5"
                	"fmt"
                	"os"
                )
                func main() {
                	for _, arg := range os.Args {
                		fmt.Printf("%x - %s\n", md5.Sum([]byte(arg)), arg)
                	}
                }
                `, analyzer)
	checkTestResults(t, issues, 2, "weak cryptographic")
}

func TestDES(t *testing.T) {
	config := map[string]interface{}{"ignoreNosec": false}
	analyzer := gas.NewAnalyzer(config, nil)
	analyzer.AddRule(NewBlacklist_crypto_des(config))
	analyzer.AddRule(NewUsesWeakCryptography(config))

	issues := gasTestRunner(`
                package main

                import (
                	"crypto/cipher"
                	"crypto/des"
                	"crypto/rand"
                	"encoding/hex"
                	"fmt"
                	"io"
                )

                func main() {
                	block, err := des.NewCipher([]byte("sekritz"))
                	if err != nil {
                		panic(err)
                	}

                	plaintext := []byte("I CAN HAZ SEKRIT MSG PLZ")
                	ciphertext := make([]byte, des.BlockSize+len(plaintext))
                	iv := ciphertext[:des.BlockSize]
                	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
                		panic(err)
                	}

                	stream := cipher.NewCFBEncrypter(block, iv)
                	stream.XORKeyStream(ciphertext[des.BlockSize:], plaintext)
                	fmt.Println("Secret message is: %s", hex.EncodeToString(ciphertext))
                }
                `, analyzer)

	checkTestResults(t, issues, 2, "weak cryptographic")
}

func TestRC4(t *testing.T) {
	config := map[string]interface{}{"ignoreNosec": false}
	analyzer := gas.NewAnalyzer(config, nil)
	analyzer.AddRule(NewBlacklist_crypto_rc4(config))
	analyzer.AddRule(NewUsesWeakCryptography(config))

	issues := gasTestRunner(`
                package main

                import (
                	"crypto/rc4"
                	"encoding/hex"
                	"fmt"
                )

                func main() {
                	cipher, err := rc4.NewCipher([]byte("sekritz"))
                	if err != nil {
                		panic(err)
                	}

                	plaintext := []byte("I CAN HAZ SEKRIT MSG PLZ")
                	ciphertext := make([]byte, len(plaintext))
                	cipher.XORKeyStream(ciphertext, plaintext)
                	fmt.Println("Secret message is: %s", hex.EncodeToString(ciphertext))
                }
                `, analyzer)

	checkTestResults(t, issues, 2, "weak cryptographic")
}
