package main

import (
	"flag"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestMapTLSVersions(t *testing.T) {
	t.Parallel()

	versions := mapTLSVersions([]string{"TLSv1.3", "TLSv1", "unknown", "TLSv1.2"})
	expected := []int{0x0301, 0x0303, 0x0304}
	if !reflect.DeepEqual(versions, expected) {
		t.Fatalf("unexpected mapped versions: got %v want %v", versions, expected)
	}
}

func TestGetTLSConfFromURL(t *testing.T) {
	t.Parallel()

	t.Run("decodes valid JSON", func(t *testing.T) {
		t.Parallel()

		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(`{"version": 1.0, "configurations": {"modern": {"tls_versions": ["TLSv1.3"]}}}`))
		}))
		defer srv.Close()

		conf, err := getTLSConfFromURL(srv.URL)
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
		if conf == nil {
			t.Fatalf("expected configuration, got nil")
		}
		if conf.Version != 1.0 {
			t.Fatalf("unexpected version: got %v", conf.Version)
		}
	})

	t.Run("returns error on invalid JSON", func(t *testing.T) {
		t.Parallel()

		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(`{invalid`))
		}))
		defer srv.Close()

		conf, err := getTLSConfFromURL(srv.URL)
		if err == nil {
			t.Fatalf("expected error, got nil")
		}
		if conf != nil {
			t.Fatalf("expected nil configuration on decode error")
		}
	})
}

func TestGetGoCipherConfig(t *testing.T) {
	t.Parallel()

	t.Run("returns error for missing named configuration", func(t *testing.T) {
		t.Parallel()

		_, err := getGoCipherConfig("modern", ServerSideTLSJson{Configurations: map[string]Configuration{}})
		if err == nil {
			t.Fatalf("expected error for missing configuration")
		}
	})

	t.Run("returns error when no TLS versions map", func(t *testing.T) {
		t.Parallel()

		input := ServerSideTLSJson{
			Configurations: map[string]Configuration{
				"modern": {
					OpenSSLCiphersuites: []string{"TLS_AES_128_GCM_SHA256"},
					TLSVersions:         []string{"SSLv3"},
				},
			},
		}

		_, err := getGoCipherConfig("modern", input)
		if err == nil {
			t.Fatalf("expected error when TLS versions are unmapped")
		}
	})

	t.Run("maps TLS versions and preserves IANA cipher names", func(t *testing.T) {
		t.Parallel()

		input := ServerSideTLSJson{
			Configurations: map[string]Configuration{
				"modern": {
					OpenSSLCiphersuites: []string{"TLS_AES_128_GCM_SHA256"},
					TLSVersions:         []string{"TLSv1.3", "TLSv1.2"},
				},
			},
		}

		conf, err := getGoCipherConfig("modern", input)
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}

		if conf.Name != "Modern" {
			t.Fatalf("unexpected normalized name: got %q", conf.Name)
		}
		if conf.MinVersion != "0x0303" || conf.MaxVersion != "0x0304" {
			t.Fatalf("unexpected TLS bounds: min=%s max=%s", conf.MinVersion, conf.MaxVersion)
		}
		if len(conf.Ciphers) != 1 || conf.Ciphers[0] != "TLS_AES_128_GCM_SHA256" {
			t.Fatalf("unexpected ciphers: %v", conf.Ciphers)
		}
	})
}

func TestGetCurrentDir(t *testing.T) {
	t.Parallel()

	originalCommandLine := flag.CommandLine
	defer func() {
		flag.CommandLine = originalCommandLine
	}()

	newFlagSet := func(args ...string) {
		flag.CommandLine = flag.NewFlagSet("test", flag.ContinueOnError)
		_ = flag.CommandLine.Parse(args)
	}

	t.Run("returns cwd when no args provided", func(t *testing.T) {
		newFlagSet()
		dir, err := getCurrentDir()
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}

		expected, err := filepath.Abs(".")
		if err != nil {
			t.Fatalf("failed to resolve expected abs path: %v", err)
		}
		if dir != expected {
			t.Fatalf("unexpected dir: got %q want %q", dir, expected)
		}
	})

	t.Run("returns provided absolute path for single arg", func(t *testing.T) {
		tempDir := t.TempDir()
		newFlagSet(tempDir)

		dir, err := getCurrentDir()
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}

		expected, err := filepath.Abs(tempDir)
		if err != nil {
			t.Fatalf("failed to resolve expected abs path: %v", err)
		}
		if dir != expected {
			t.Fatalf("unexpected dir: got %q want %q", dir, expected)
		}
	})

	t.Run("returns error when more than one arg is provided", func(t *testing.T) {
		tempA := t.TempDir()
		tempB := filepath.Join(os.TempDir(), "another-dir")
		newFlagSet(tempA, tempB)

		dir, err := getCurrentDir()
		if err == nil {
			t.Fatalf("expected error, got dir=%q", dir)
		}
	})
}
