package testutils

import "github.com/securego/gosec/v2"

// SampleCodeG302 - file create / chmod permissions check
var SampleCodeG302 = []CodeSample{
	{[]string{`
package main

import (
	"fmt"
	"os"
)

func main() {
	err := os.Chmod("/tmp/somefile", 0777)
	if err != nil {
		fmt.Println("Error when changing file permissions!")
		return
	}
}
`}, 1, gosec.NewConfig()},
	{[]string{`
package main

import (
	"fmt"
	"os"
)

func main() {
	_, err := os.OpenFile("/tmp/thing", os.O_CREATE|os.O_WRONLY, 0666)
	if err != nil {
		fmt.Println("Error opening a file!")
		return
	}
}
`}, 1, gosec.NewConfig()},
	{[]string{`
package main

import (
	"fmt"
	"os"
)

func main() {
	err := os.Chmod("/tmp/mydir", 0400)
	if err != nil {
		fmt.Println("Error")
		return
	}
}
`}, 0, gosec.NewConfig()},
	{[]string{`
package main

import (
	"fmt"
	"os"
)

func main() {
	_, err := os.OpenFile("/tmp/thing", os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		fmt.Println("Error opening a file!")
		return
	}
}
`}, 0, gosec.NewConfig()},
	{[]string{`
package main

import "os"

const weakChmodPerm = 0777

func main() {
	_ = os.Chmod("/tmp/somefile", weakChmodPerm)
}
`}, 1, gosec.NewConfig()},
	{[]string{`
package main

import "os"

func main() {
	_, _ = os.OpenFile("/tmp/thing", os.O_CREATE|os.O_WRONLY, 0600|0066)
}
`}, 1, gosec.NewConfig()},
	{[]string{`
package main

import "os"

const safeFilePerm = 0600

func main() {
	_ = os.Chmod("/tmp/somefile", safeFilePerm)
	_, _ = os.OpenFile("/tmp/thing", os.O_CREATE|os.O_WRONLY, os.FileMode(safeFilePerm))
}
`}, 0, gosec.NewConfig()},
}
