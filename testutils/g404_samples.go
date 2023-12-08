package testutils

import "github.com/securego/gosec/v2"

// SampleCodeG404 - weak random number
var SampleCodeG404 = []CodeSample{
	{[]string{`
package main

import "crypto/rand"

func main() {
	good, _ := rand.Read(nil)
	println(good)
}
`}, 0, gosec.NewConfig()},
	{[]string{`
package main

import "math/rand"

func main() {
	bad := rand.Int()
	println(bad)
}
`}, 1, gosec.NewConfig()},
	{[]string{`
package main

import (
	"crypto/rand"
	mrand "math/rand"
)

func main() {
	good, _ := rand.Read(nil)
	println(good)
	bad := mrand.Int31()
	println(bad)
}
`}, 1, gosec.NewConfig()},
	{[]string{`
package main

import (
	"math/rand"
)

func main() {
	gen := rand.New(rand.NewSource(10))
	bad := gen.Int()
	println(bad)
}
`}, 1, gosec.NewConfig()},
	{[]string{`
package main

import (
	"math/rand"
)

func main() {
	bad := rand.Intn(10)
	println(bad)
}
`}, 1, gosec.NewConfig()},
	{[]string{`
package main

import (
	"crypto/rand"
	"math/big"
	rnd "math/rand"
)

func main() {
	good, _ := rand.Int(rand.Reader, big.NewInt(int64(2)))
	println(good)
	bad := rnd.Intn(2)
	println(bad)
}
`}, 1, gosec.NewConfig()},
	{[]string{`
package main

import (
	crand "crypto/rand"
	"math/big"
	"math/rand"
	rand2 "math/rand"
	rand3 "math/rand"
)

func main() {
	_, _ = crand.Int(crand.Reader, big.NewInt(int64(2))) // good

	_ = rand.Intn(2) // bad
	_ = rand2.Intn(2)  // bad
	_ = rand3.Intn(2)  // bad
}
`}, 3, gosec.NewConfig()},
}
