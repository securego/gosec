package testutils

import "github.com/securego/gosec/v2"

// SampleCodeG409 - weak bcrypt cost
var SampleCodeG409 = []CodeSample{
	{[]string{`
package main

import (
	"fmt"

	"golang.org/x/crypto/bcrypt"
)

func main() {
	hash, err := bcrypt.GenerateFromPassword([]byte("hunter2"), 4)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(string(hash))
}
`}, 1, gosec.NewConfig()},

	{[]string{`
package main

import (
	"fmt"

	"golang.org/x/crypto/bcrypt"
)

func main() {
	hash, err := bcrypt.GenerateFromPassword([]byte("hunter2"), 8)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(string(hash))
}
`}, 1, gosec.NewConfig()},

	{[]string{`
package main

import (
	"fmt"

	"golang.org/x/crypto/bcrypt"
)

func main() {
	hash, err := bcrypt.GenerateFromPassword([]byte("hunter2"), 10)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(string(hash))
}
`}, 0, gosec.NewConfig()},

	{[]string{`
package main

import (
	"fmt"

	"golang.org/x/crypto/bcrypt"
)

func main() {
	hash, err := bcrypt.GenerateFromPassword([]byte("hunter2"), 12)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(string(hash))
}
`}, 0, gosec.NewConfig()},
}
