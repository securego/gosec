package testutils

import "github.com/securego/gosec/v2"

// SampleCodeG403 - weak key strength
var SampleCodeG403 = []CodeSample{
	{[]string{`
package main

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
)

func main() {
	//Generate Private Key
	pvk, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(pvk)
}
`}, 1, gosec.NewConfig()},
	{[]string{`
package main

import (
	"crypto/rand"
	"crypto/rsa"
)

const weakKeyBits = 1024

func main() {
	_, _ = rsa.GenerateKey(rand.Reader, weakKeyBits)
}
`}, 1, gosec.NewConfig()},
	{[]string{`
package main

import (
	"crypto/rand"
	"crypto/rsa"
)

func main() {
	_, _ = rsa.GenerateKey(rand.Reader, 1<<10)
}
`}, 1, gosec.NewConfig()},
	{[]string{`
package main

import (
	"crypto/rand"
	"crypto/rsa"
)

const secureKeyBits = 2048

func main() {
	_, _ = rsa.GenerateKey(rand.Reader, secureKeyBits)
}
`}, 0, gosec.NewConfig()},
	// Runtime values are unknown and must not be reported as weak constants.
	{[]string{`
package main

import (
	"crypto/rand"
	"crypto/rsa"
)

func generate(bits int) {
	_, _ = rsa.GenerateKey(rand.Reader, bits)
}
`}, 0, gosec.NewConfig()},
}
