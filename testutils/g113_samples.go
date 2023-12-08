package testutils

import "github.com/securego/gosec/v2"

// SampleCodeG113 - Usage of Rat.SetString in math/big with an overflow
var SampleCodeG113 = []CodeSample{
	{[]string{`
package main

import (
	"math/big"
	"fmt"
)

func main() {
	r := big.Rat{}
	r.SetString("13e-9223372036854775808")

	fmt.Println(r)
}
`}, 1, gosec.NewConfig()},
}
