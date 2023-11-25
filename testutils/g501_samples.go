package testutils

import "github.com/securego/gosec/v2"

var (
	// SampleCodeG501 - Blocklisted import MD5
	SampleCodeG501 = []CodeSample{
		{[]string{`
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
`}, 1, gosec.NewConfig()},
	}
)
