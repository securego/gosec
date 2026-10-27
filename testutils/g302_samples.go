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
	{[]string{`
package main

import "os"

func main() {
	f, err := os.Create("/tmp/somefile")
	if err != nil {
		return
	}
	defer f.Close()
	_ = f.Chmod(0777)
}
`}, 1, gosec.NewConfig()},
	{[]string{`
package main

import "os"

type logFile struct {
	*os.File
}

func main() {
	f, err := os.OpenFile("/tmp/somefile", os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return
	}
	lf := logFile{f}
	_ = lf.Chmod(os.ModePerm)
}
`}, 1, gosec.NewConfig()},
	{[]string{`
package main

import "os"

func main() {
	f, err := os.Create("/tmp/somefile")
	if err != nil {
		return
	}
	defer f.Close()
	_ = f.Chmod(0600)
}
`}, 0, gosec.NewConfig()},
	{[]string{`
package main

type file struct{}

func (file) Chmod(mode uint32) error { return nil }

func main() {
	var f file
	_ = f.Chmod(0777)
}
`}, 0, gosec.NewConfig()},
	{[]string{`
package main

import "os"

func main() {
	root, err := os.OpenRoot("/tmp")
	if err != nil {
		return
	}
	defer root.Close()
	f, err := root.OpenFile("thing", os.O_CREATE|os.O_WRONLY, 0666)
	if err != nil {
		return
	}
	defer f.Close()
	_ = root.Chmod("somefile", 0777)
}
`}, 2, gosec.NewConfig()},
	{[]string{`
package main

import "os"

func main() {
	root, err := os.OpenRoot("/tmp")
	if err != nil {
		return
	}
	defer root.Close()
	f, err := root.OpenFile("thing", os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return
	}
	defer f.Close()
	_ = root.Chmod("somefile", 0400)
}
`}, 0, gosec.NewConfig()},
}
