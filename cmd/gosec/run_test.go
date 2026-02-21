package main

import (
	"errors"
	"flag"
	"os"
	"os/exec"
	"testing"

	"github.com/securego/gosec/v2/cmd/vflag"
)

func TestRun_NoInputReturnsFailure(t *testing.T) {
	t.Parallel()

	code := runInSubprocess(t, "no-input")
	if code != exitFailure {
		t.Fatalf("unexpected exit code: got %d want %d", code, exitFailure)
	}
}

func TestRun_VersionReturnsSuccess(t *testing.T) {
	t.Parallel()

	code := runInSubprocess(t, "version")
	if code != exitSuccess {
		t.Fatalf("unexpected exit code: got %d want %d", code, exitSuccess)
	}
}

func runInSubprocess(t *testing.T, scenario string) int {
	t.Helper()

	executable, err := os.Executable()
	if err != nil {
		t.Fatalf("failed to resolve test executable: %v", err)
	}

	cmd := exec.Command(executable, "-test.run=^TestRunHelperProcess$")
	cmd.Env = append(os.Environ(), "GOSEC_RUN_HELPER=1", "GOSEC_RUN_SCENARIO="+scenario)

	err = cmd.Run()
	if err == nil {
		return 0
	}

	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) {
		t.Fatalf("failed to run helper process: %v", err)
	}

	return exitErr.ExitCode()
}

func TestRunHelperProcess(t *testing.T) {
	_ = t

	if os.Getenv("GOSEC_RUN_HELPER") != "1" {
		return
	}

	scenario := os.Getenv("GOSEC_RUN_SCENARIO")

	flag.CommandLine = flag.NewFlagSet("gosec-helper", flag.ContinueOnError)
	os.Args = []string{"gosec"}

	*flagIgnoreNoSec = false
	*flagShowIgnored = false
	*flagAlternativeNoSec = ""
	*flagEnableAudit = false
	*flagOutput = ""
	*flagConfig = ""
	*flagQuiet = true
	*flagRulesInclude = ""
	flagRulesExclude = vflag.ValidatedFlag{}
	*flagExcludeGenerated = false
	*flagLogfile = ""
	*flagSortIssues = true
	*flagBuildTags = ""
	*flagSeverity = "low"
	*flagConfidence = "low"
	*flagNoFail = false
	*flagScanTests = false
	*flagVersion = false
	*flagStdOut = false
	*flagColor = false
	*flagRecursive = false
	*flagVerbose = ""
	*flagTrackSuppressions = false
	*flagTerse = false
	*flagAiAPIProvider = ""
	*flagAiAPIKey = ""
	*flagAiBaseURL = ""
	*flagAiSkipSSL = false
	flagDirsExclude = nil

	if scenario == "version" {
		*flagVersion = true
	}

	os.Exit(run())
}
