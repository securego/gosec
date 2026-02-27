package testutils

import "github.com/securego/gosec/v2"

// SampleCodeG705 - XSS via taint analysis
var SampleCodeG705 = []CodeSample{
	{[]string{`
package main

import (
	"fmt"
	"net/http"
)

func handler(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	fmt.Fprintf(w, "<h1>Hello %s</h1>", name)
}
`}, 1, gosec.NewConfig()},
	{[]string{`
package main

import (
	"net/http"
)

func writeHandler(w http.ResponseWriter, r *http.Request) {
	data := r.FormValue("data")
	w.Write([]byte(data))
}
`}, 1, gosec.NewConfig()},
	{[]string{`
package main

import (
	"fmt"
	"net/http"
	"html"
)

func safeHandler(w http.ResponseWriter, r *http.Request) {
	// Safe - escaped output
	name := r.URL.Query().Get("name")
	fmt.Fprintf(w, "<h1>Hello %s</h1>", html.EscapeString(name))
}
`}, 0, gosec.NewConfig()},
	{[]string{`
package main

import (
	"fmt"
	"net/http"
)

func staticHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "<h1>Hello World</h1>")
}
`}, 0, gosec.NewConfig()},
	// Test: json.Marshal sanitizer
	{[]string{`
package main

import (
	"encoding/json"
	"net/http"
)

func handler(w http.ResponseWriter, r *http.Request) {
	data := r.FormValue("data")
	jsonData, _ := json.Marshal(data)
	w.Write(jsonData)
}
`}, 0, gosec.NewConfig()},
	// Test: strconv sanitizer
	{[]string{`
package main

import (
	"net/http"
	"strconv"
)

func handler(w http.ResponseWriter, r *http.Request) {
	id := r.FormValue("id")
	num, _ := strconv.Atoi(id)
	w.Write([]byte(strconv.Itoa(num)))
}
`}, 0, gosec.NewConfig()},
	// Test: context.Context should not propagate taint from *http.Request
	// This is the pattern from PR #1543 — r.Context() passed to a function
	// should not taint the function's return value.
	{[]string{`
package main

import (
	"context"
	"net/http"
)

type service struct{}

func (s *service) GetData(ctx context.Context, id string) ([]byte, error) {
	return []byte("safe data"), nil
}

func handler(w http.ResponseWriter, r *http.Request) {
	svc := &service{}
	data, _ := svc.GetData(r.Context(), "static-id")
	w.Write(data)
}
`}, 0, gosec.NewConfig()},

	// G705 must NOT fire because the writer argument
	// is not net/http.ResponseWriter.
	{[]string{`
package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"sync"
)

type Masker struct{}

func (m *Masker) MaskSecrets(in string) string { return in }

func streamOutput(pipe io.Reader, outW io.Writer, wg *sync.WaitGroup) {
	defer wg.Done()
	masker := &Masker{}
	reader := bufio.NewReader(pipe)
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			break
		}
		line = strings.TrimSuffix(line, "\r")
		if _, writeErr := fmt.Fprint(outW, masker.MaskSecrets(line)); writeErr != nil {
			break
		}
	}
}

func main() {
	cmd := exec.Command("echo", "hello world")
	stdoutPipe, _ := cmd.StdoutPipe()
	stderrPipe, _ := cmd.StderrPipe()
	_ = cmd.Start()
	var wg sync.WaitGroup
	wg.Add(2)
	go streamOutput(stdoutPipe, os.Stdout, &wg)
	go streamOutput(stderrPipe, os.Stderr, &wg)
	wg.Wait()
}
`}, 0, gosec.NewConfig()},
	// G705 must NOT fire because the writer argument
	// is not net/http.ResponseWriter.
	{[]string{`
package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Fprint(os.Stdout, os.Args[1])
}
`}, 0, gosec.NewConfig()},

	// TRUE POSITIVE: exec output piped directly to http.ResponseWriter.
	// G705 MUST fire — the writer IS http.ResponseWriter.
	{[]string{`
package main

import (
	"fmt"
	"net/http"
	"os/exec"
)

func handler(w http.ResponseWriter, r *http.Request) {
	param := r.URL.Query().Get("cmd")
	out, _ := exec.Command("sh", "-c", param).Output()
	fmt.Fprint(w, string(out))
}

func main() {
	http.HandleFunc("/run", handler)
	_ = http.ListenAndServe(":8080", nil)
}
`}, 1, gosec.NewConfig()},
}
