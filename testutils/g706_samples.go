package testutils

import "github.com/securego/gosec/v2"

// SampleCodeG706 - Log injection via taint analysis
var SampleCodeG706 = []CodeSample{
	// ── slog regression tests (issue #1622) ──────────────────────────────────
	// slog.Warn/Error/Info/Debug pass attribute values through structured
	// handlers (TextHandler, JSONHandler) that escape them automatically.
	// Tainted values in key-value attribute pairs must NOT be flagged.
	{[]string{`
package main

import (
	"log/slog"
	"net/http"
)

func handler(r *http.Request) {
	// Exact pattern from issue #1622 - must not trigger G706.
	slog.Error("request failed", "err", "some err", "uri", r.RequestURI)
}
`}, 0, gosec.NewConfig()},
	{[]string{`
package main

import (
	"log/slog"
	"net/http"
)

func handler(r *http.Request) {
	// Exact pattern from issue #1622, but for Context - must not trigger G706.
	slog.ErrorContext(r.Context(), "request failed", "err", "some err", "uri", r.RequestURI)
}
`}, 0, gosec.NewConfig()},
	{[]string{`
package main

import (
	"log/slog"
	"net/http"
)

func handler(r *http.Request) {
	logger := slog.Default()

	// Exact pattern from issue #1622, but for Logger - must not trigger G706.
	logger.Error("request failed", "err", "some err", "uri", r.RequestURI)
}
`}, 0, gosec.NewConfig()},
	{[]string{`
package main

import (
	"log/slog"
	"net/http"
)

func handler(r *http.Request) {
	// Exact pattern from issue #1622 - must not trigger G706.
	fileExtension := r.URL.Query().Get("ext")
	slog.Warn("Error getting FS to serve", "ext", fileExtension, "path", r.URL.Path)
}
`}, 0, gosec.NewConfig()},
	{[]string{`
package main

import (
	"log/slog"
	"net/http"
)

func handler(r *http.Request) {
	// Exact pattern from issue #1622, but for Context - must not trigger G706.
	fileExtension := r.URL.Query().Get("ext")
	slog.WarnContext(r.Context(), "Error getting FS to serve",
		"ext", fileExtension,
		"path", r.URL.Path)
}
`}, 0, gosec.NewConfig()},
	{[]string{`
package main

import (
	"log/slog"
	"net/http"
)

func handler(r *http.Request) {
	logger := slog.Default()

	// Exact pattern from issue #1622 - must not trigger G706.
	fileExtension := r.URL.Query().Get("ext")
	logger.Warn("Error getting FS to serve",
		"ext", fileExtension,
		"path", r.URL.Path)
}
`}, 0, gosec.NewConfig()},
	{[]string{`
package main

import (
	"log/slog"
	"net/http"
)

func handler(r *http.Request) {
	// Multiple tainted attribute values - must not trigger G706.
	filePath := r.URL.Path
	slog.Warn("Error getting HLS file info", "path", filePath)
}
`}, 0, gosec.NewConfig()},
	{[]string{`
package main

import (
	"log/slog"
	"net/http"
)

func handler(r *http.Request) {
	// Multiple tainted attribute values - must not trigger G706.
	filePath := r.URL.Path
	slog.WarnContext(r.Context(), "Error getting HLS file info",
		"path", filePath)
}
`}, 0, gosec.NewConfig()},
	{[]string{`
package main

import (
	"log/slog"
	"net/http"
)

func handler(r *http.Request) {
	// Multiple tainted attribute values - must not trigger G706.
	filePath := r.URL.Path

	slog.Log(r.Context(), slog.LevelWarn-1, "Error getting HLS file info",
		"path", filePath)
}
`}, 0, gosec.NewConfig()},
	{[]string{`
package main

import (
	"log/slog"
	"net/http"
)

func handler(r *http.Request) {
	// Multiple tainted attribute values - must not trigger G706.
	filePath := r.URL.Path

	slog.LogAttrs(r.Context(), slog.LevelWarn-1, "Error getting HLS file info",
		slog.String("path", filePath))
}
`}, 0, gosec.NewConfig()},
	{[]string{`
package main

import (
	"log/slog"
	"net/http"
)

func handler(r *http.Request) {
	logger := slog.Default()

	// Multiple tainted attribute values - must not trigger G706.
	filePath := r.URL.Path

	logger.Log(r.Context(), slog.LevelWarn-1, "Error getting HLS file info",
		"path", filePath)
}
`}, 0, gosec.NewConfig()},
	// Tainted slog message (args[0]) IS a real injection vector -
	// TextHandler writes msg verbatim; this MUST still be flagged.
	{[]string{`
package main

import (
	"log/slog"
	"net/http"
)

func handler(r *http.Request) {
	msg := r.URL.Query().Get("msg")
	slog.Warn(msg) // tainted message - should be flagged
}
`}, 1, gosec.NewConfig()},
	{[]string{`
package main

import (
	"log/slog"
	"net/http"
)

func handler(r *http.Request) {
	msg := r.URL.Query().Get("msg")
	slog.WarnContext(r.Context(), msg) // tainted message - should be flagged
}
`}, 1, gosec.NewConfig()},
	{[]string{`
package main

import (
	"log/slog"
	"net/http"
)

func handler(r *http.Request) {
	msg := r.URL.Query().Get("msg")
	slog.Log(r.Context(), slog.LevelWarn+1, msg) // tainted message - should be flagged
}
`}, 1, gosec.NewConfig()},
	{[]string{`
package main

import (
	"log/slog"
	"net/http"
)

func handler(r *http.Request) {
	logger := slog.Default()
	msg := r.URL.Query().Get("msg")
	logger.Log(r.Context(), slog.LevelWarn+1, msg) // tainted message - should be flagged
}
`}, 1, gosec.NewConfig()},
	// ── original test cases ───────────────────────────────────────────────────
	{[]string{`
package main

import (
	"log"
	"net/http"
)

func handler(r *http.Request) {
	username := r.URL.Query().Get("user")
	log.Printf("User logged in: %s", username)
}
`}, 1, gosec.NewConfig()},
	{[]string{`
package main

import (
	"log"
	"os"
)

func logArgs() {
	input := os.Args[1]
	log.Println("Processing:", input)
}
`}, 1, gosec.NewConfig()},
	{[]string{`
package main

import (
	"log"
)

func safeLog() {
	// Safe - no user input
	log.Println("Application started")
}
`}, 0, gosec.NewConfig()},
	// Test: json.Marshal sanitizer
	{[]string{`
package main

import (
	"encoding/json"
	"log"
	"net/http"
)

func handler(r *http.Request) {
	data := r.FormValue("data")
	jsonData, _ := json.Marshal(data)
	log.Printf("Received: %s", jsonData)
}
`}, 0, gosec.NewConfig()},
	// Test: strconv sanitizer
	{[]string{`
package main

import (
	"log"
	"net/http"
	"strconv"
)

func handler(r *http.Request) {
	id := r.FormValue("id")
	num, _ := strconv.Atoi(id)
	log.Printf("Processing ID: %d", num)
}
`}, 0, gosec.NewConfig()},
}
