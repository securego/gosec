package testutils

import "github.com/securego/gosec/v2"

// SampleCodeG704 - SSRF via taint analysis
var SampleCodeG704 = []CodeSample{
	{[]string{`
package main

import (
	"net/http"
)

func handler(r *http.Request) {
	url := r.URL.Query().Get("url")
	http.Get(url)
}
`}, 1, gosec.NewConfig()},
	{[]string{`
package main

import (
	"net/http"
	"os"
)

func fetchFromEnv() {
	target := os.Getenv("TARGET_URL")
	http.Post(target, "text/plain", nil)
}
`}, 1, gosec.NewConfig()},
	{[]string{`
package main

import (
	"net/http"
)

func safeRequest() {
	// Safe - hardcoded URL
	http.Get("https://api.example.com/data")
}
`}, 0, gosec.NewConfig()},
	{[]string{`
package main

import (
	"context"
	"net/http"
	"time"
)

func GetPublicIP() (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://am.i.mullvad.net/ip", nil)
	if err != nil {
		return "", err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	return "", nil
}
`}, 0, gosec.NewConfig()},
	// Constant URL string must NOT trigger G704.
	{[]string{`
package main

import (
	"context"
	"net/http"
)

const url = "https://go.dev/"

func main() {
	ctx := context.Background()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
	if err != nil {
		panic(err)
	}
	_, err = new(http.Client).Do(req)
	if err != nil {
		panic(err)
	}
}
`}, 0, gosec.NewConfig()},
	// Sanity check: variable URL from request still fires.
	{[]string{`
package main

import (
	"net/http"
)

func handler(r *http.Request) {
	target := r.URL.Query().Get("url")
	http.Get(target) //nolint:errcheck
}
`}, 1, gosec.NewConfig()},
	// Wrapper method with hardcoded URL must NOT trigger G704.
	// The *http.Request parameter in the wrapper is safe because
	// all callers pass a request built from a constant URL.
	{[]string{`
package main

import (
	"context"
	"fmt"
	"net/http"
)

type HTTPDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

type NamedClient struct {
	HTTPClient *http.Client
}

func (c *NamedClient) Do(req *http.Request) (*http.Response, error) {
	req.Header.Set("User-Agent", "test-agent")
	return c.HTTPClient.Do(req)
}

func doImport(httpDoer HTTPDoer) error {
	ctx := context.Background()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "/import", http.NoBody)
	if err != nil {
		return fmt.Errorf("creating import POST: %w", err)
	}
	resp, err := httpDoer.Do(req)
	if err != nil {
		return fmt.Errorf("performing import POST: %w", err)
	}
	defer resp.Body.Close()
	return nil
}

func main() {
	client := &NamedClient{HTTPClient: http.DefaultClient}
	_ = doImport(client)
}
`}, 0, gosec.NewConfig()},
	// Wrapper method with tainted URL MUST trigger G704.
	// Two sinks fire: NewRequest (tainted URL arg) and the inner Client.Do
	// (tainted request flows through the call graph to the wrapper's parameter).
	{[]string{`
package main

import (
	"net/http"
	"os"
)

type APIClient struct {
	HTTPClient *http.Client
}

func (c *APIClient) Do(req *http.Request) (*http.Response, error) {
	return c.HTTPClient.Do(req)
}

func main() {
	client := &APIClient{HTTPClient: http.DefaultClient}
	url := os.Getenv("TARGET_URL")
	req, _ := http.NewRequest(http.MethodGet, url, nil)
	client.Do(req)
}
`}, 2, gosec.NewConfig()},
}
