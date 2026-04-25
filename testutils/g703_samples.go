package testutils

import "github.com/securego/gosec/v2"

// SampleCodeG703 - Path traversal via taint analysis
var SampleCodeG703 = []CodeSample{
	// True positive: HTTP request parameter used as file path
	{[]string{`
package main

import (
	"net/http"
	"os"
)

func handler(r *http.Request) {
	path := r.URL.Query().Get("file")
	os.Open(path)
}
`}, 1, gosec.NewConfig()},
	{[]string{`
package main

import (
	"net/http"
	"os"
)

func writeHandler(r *http.Request) {
	filename := r.FormValue("name")
	os.WriteFile(filename, []byte("data"), 0644)
}
`}, 1, gosec.NewConfig()},
	{[]string{`
package main

import (
	"os"
)

func safeOpen() {
	// Safe - no user input
	os.Open("/var/log/app.log")
}
`}, 0, gosec.NewConfig()},
	{[]string{`
package main

import (
	"io/fs"
	"os"
	"path/filepath"
)

func Foo() {
	var docName string
	err := filepath.WalkDir(".", func(fpath string, d fs.DirEntry, err error) error {
		if err == nil {
			if d.Type().IsRegular() {
				docName = d.Name()
			}
		}
		return nil
	})

	if err == nil && docName != "" {
		var f *os.File
		if f, err = os.Open(docName); err == nil {
			defer f.Close()
		}
	}
}
`}, 0, gosec.NewConfig()},
	{[]string{`
package main

import (
	"os"
)

func openFromArgs() {
	if len(os.Args) > 1 {
		os.Open(os.Args[1])
	}
}
`}, 1, gosec.NewConfig()},
	{[]string{`
package main

import (
	"net/http"
	"os"
	"path/filepath"
)

func safeHandler(r *http.Request) {
	raw := r.URL.Query().Get("file")
	cleaned := filepath.Clean(raw)
	os.Open(cleaned)
}
`}, 0, gosec.NewConfig()},
	// Test: path.Base sanitizer
	{[]string{`
package main

import (
	"net/http"
	"os"
	"path"
)

func handler(r *http.Request) {
	userFile := r.FormValue("file")
	safe := path.Base(userFile)
	os.Open(safe)
}
`}, 0, gosec.NewConfig()},
	// Safe: filepath.Abs sanitizer (calls Clean internally)
	{[]string{`
package main

import (
	"os"
	"path/filepath"
)

func main() {
	filename := os.Getenv("FILE")
	filename, _ = filepath.Abs(filename)
	os.ReadFile(filename)
}
`}, 0, gosec.NewConfig()},
	// Test: strconv sanitizer
	{[]string{`
package main

import (
	"net/http"
	"os"
	"strconv"
)

func handler(r *http.Request) {
	id := r.FormValue("id")
	num, _ := strconv.Atoi(id)
	os.Open("/tmp/file" + strconv.Itoa(num))
}
`}, 0, gosec.NewConfig()},
	// True positive: http.ServeFile with user-controlled path
	{[]string{`
package main

import (
	"net/http"
)

func handler(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Query().Get("file")
	http.ServeFile(w, r, path)
}
`}, 1, gosec.NewConfig()},
	// True positive: http.ServeFileFS with user-controlled path
	{[]string{`
package main

import (
	"net/http"
	"os"
)

func handler(w http.ResponseWriter, r *http.Request) {
	name := r.FormValue("name")
	http.ServeFileFS(w, r, os.DirFS("."), name)
}
`}, 1, gosec.NewConfig()},
	// True negative: http.ServeFile with hardcoded path
	{[]string{`
package main

import (
	"net/http"
)

func handler(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "static/index.html")
}
`}, 0, gosec.NewConfig()},
}
