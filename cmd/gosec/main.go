// (c) Copyright 2016 Hewlett Packard Enterprise Development LP
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"runtime"
	"sort"
	"strings"

	"github.com/securego/gosec/v2"
	"github.com/securego/gosec/v2/cmd/vflag"
	"github.com/securego/gosec/v2/report"
	"github.com/securego/gosec/v2/rules"
)

const (
	usageText = `
gosec - Golang security checker

gosec analyzes Go source code to look for common programming mistakes that
can lead to security problems.

VERSION: %s
GIT TAG: %s
BUILD DATE: %s

USAGE:

	# Check a single package
	$ gosec $GOPATH/src/github.com/example/project

	# Check all packages under the current directory and save results in
	# json format.
	$ gosec -fmt=json -out=results.json ./...

	# Run a specific set of rules (by default all rules will be run):
	$ gosec -include=G101,G203,G401  ./...

	# Run all rules except the provided
	$ gosec -exclude=G101 $GOPATH/src/github.com/example/project/...

`
)

type arrayFlags []string

func (a *arrayFlags) String() string {
	return strings.Join(*a, " ")
}

func (a *arrayFlags) Set(value string) error {
	*a = append(*a, value)
	return nil
}

var (
	//#nosec flag
	flagIgnoreNoSec = flag.Bool("nosec", false, "Ignores #nosec comments when set")

	// show ignored
	flagShowIgnored = flag.Bool("show-ignored", false, "If enabled, ignored issues are printed")

	// format output
	flagFormat = flag.String("fmt", "text", "Set output format. Valid options are: json, yaml, csv, junit-xml, html, sonarqube, golint, sarif or text")

	//#nosec alternative tag
	flagAlternativeNoSec = flag.String("nosec-tag", "", "Set an alternative string for #nosec. Some examples: #dontanalyze, #falsepositive")

	// output file
	flagOutput = flag.String("out", "", "Set output file for results")

	// config file
	flagConfig = flag.String("conf", "", "Path to optional config file")

	// quiet
	flagQuiet = flag.Bool("quiet", false, "Only show output when errors are found")

	// rules to explicitly include
	flagRulesInclude = flag.String("include", "", "Comma separated list of rules IDs to include. (see rule list)")

	// rules to explicitly exclude
	flagRulesExclude = vflag.ValidatedFlag{}

	// rules to explicitly exclude
	flagExcludeGenerated = flag.Bool("exclude-generated", false, "Exclude generated files")

	// log to file or stderr
	flagLogfile = flag.String("log", "", "Log messages to file rather than stderr")
	// sort the issues by severity
	flagSortIssues = flag.Bool("sort", true, "Sort issues by severity")

	// go build tags
	flagBuildTags = flag.String("tags", "", "Comma separated list of build tags")

	// fail by severity
	flagSeverity = flag.String("severity", "low", "Filter out the issues with a lower severity than the given value. Valid options are: low, medium, high")

	// fail by confidence
	flagConfidence = flag.String("confidence", "low", "Filter out the issues with a lower confidence than the given value. Valid options are: low, medium, high")

	// concurrency value
	flagConcurrency = flag.Int("concurrency", runtime.NumCPU(), "Concurrency value")

	// do not fail
	flagNoFail = flag.Bool("no-fail", false, "Do not fail the scanning, even if issues were found")

	// scan tests files
	flagScanTests = flag.Bool("tests", false, "Scan tests files")

	// print version and quit with exit code 0
	flagVersion = flag.Bool("version", false, "Print version and quit with exit code 0")

	// stdout the results as well as write it in the output file
	flagStdOut = flag.Bool("stdout", false, "Stdout the results as well as write it in the output file")

	// print the text report with color, this is enabled by default
	flagColor = flag.Bool("color", true, "Prints the text format report with colorization when it goes in the stdout")

	// overrides the output format when stdout the results while saving them in the output file
	flagVerbose = flag.String("verbose", "", "Overrides the output format when stdout the results while saving them in the output file.\nValid options are: json, yaml, csv, junit-xml, html, sonarqube, golint, sarif or text")

	// output suppression information for auditing purposes
	flagTrackSuppressions = flag.Bool("track-suppressions", false, "Output suppression information, including its kind and justification")

	// exlude the folders from scan
	flagDirsExclude arrayFlags

	logger *log.Logger
)

//#nosec
func usage() {
	usageText := fmt.Sprintf(usageText, Version, GitTag, BuildDate)
	fmt.Fprintln(os.Stderr, usageText)
	fmt.Fprint(os.Stderr, "OPTIONS:\n\n")
	flag.PrintDefaults()
	fmt.Fprint(os.Stderr, "\n\nRULES:\n\n")

	// sorted rule list for ease of reading
	rl := rules.Generate(*flagTrackSuppressions)
	keys := make([]string, 0, len(rl.Rules))
	for key := range rl.Rules {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, k := range keys {
		v := rl.Rules[k]
		fmt.Fprintf(os.Stderr, "\t%s: %s\n", k, v.Description)
	}
	fmt.Fprint(os.Stderr, "\n")
}

func loadConfig(configFile string) (gosec.Config, error) {
	config := gosec.NewConfig()
	if configFile != "" {
		//#nosec
		file, err := os.Open(configFile)
		if err != nil {
			return nil, err
		}
		defer file.Close() //#nosec G307
		if _, err := config.ReadFrom(file); err != nil {
			return nil, err
		}
	}
	if *flagIgnoreNoSec {
		config.SetGlobal(gosec.Nosec, "true")
	}
	if *flagShowIgnored {
		config.SetGlobal(gosec.ShowIgnored, "true")
	}
	if *flagAlternativeNoSec != "" {
		config.SetGlobal(gosec.NoSecAlternative, *flagAlternativeNoSec)
	}
	// set global option IncludeRules ,when flag set or global option IncludeRules  is nil
	if v, _ := config.GetGlobal(gosec.IncludeRules); *flagRulesInclude != "" || v == "" {
		config.SetGlobal(gosec.IncludeRules, *flagRulesInclude)
	}
	// set global option ExcludeRules ,when flag set or global option IncludeRules  is nil
	if v, _ := config.GetGlobal(gosec.ExcludeRules); flagRulesExclude.String() != "" || v == "" {
		config.SetGlobal(gosec.ExcludeRules, flagRulesExclude.String())
	}
	return config, nil
}

func loadRules(include, exclude string) rules.RuleList {
	var filters []rules.RuleFilter
	if include != "" {
		logger.Printf("Including rules: %s", include)
		including := strings.Split(include, ",")
		filters = append(filters, rules.NewRuleFilter(false, including...))
	} else {
		logger.Println("Including rules: default")
	}

	if exclude != "" {
		logger.Printf("Excluding rules: %s", exclude)
		excluding := strings.Split(exclude, ",")
		filters = append(filters, rules.NewRuleFilter(true, excluding...))
	} else {
		logger.Println("Excluding rules: default")
	}
	return rules.Generate(*flagTrackSuppressions, filters...)
}

func getRootPaths(paths []string) []string {
	rootPaths := make([]string, 0)
	for _, path := range paths {
		rootPath, err := gosec.RootPath(path)
		if err != nil {
			logger.Fatal(fmt.Errorf("failed to get the root path of the projects: %w", err))
		}
		rootPaths = append(rootPaths, rootPath)
	}
	return rootPaths
}

// If verbose is defined it overwrites the defined format
// Otherwise the actual format is used
func getPrintedFormat(format string, verbose string) string {
	if verbose != "" {
		return verbose
	}
	return format
}

func printReport(format string, color bool, rootPaths []string, reportInfo *gosec.ReportInfo) error {
	err := report.CreateReport(os.Stdout, format, color, rootPaths, reportInfo)
	if err != nil {
		return err
	}
	return nil
}

func saveReport(filename, format string, rootPaths []string, reportInfo *gosec.ReportInfo) error {
	outfile, err := os.Create(filename) //#nosec G304
	if err != nil {
		return err
	}
	defer outfile.Close() //#nosec G307
	err = report.CreateReport(outfile, format, false, rootPaths, reportInfo)
	if err != nil {
		return err
	}
	return nil
}

func convertToScore(value string) (gosec.Score, error) {
	value = strings.ToLower(value)
	switch value {
	case "low":
		return gosec.Low, nil
	case "medium":
		return gosec.Medium, nil
	case "high":
		return gosec.High, nil
	default:
		return gosec.Low, fmt.Errorf("provided value '%s' not valid. Valid options: low, medium, high", value)
	}
}

func filterIssues(issues []*gosec.Issue, severity gosec.Score, confidence gosec.Score) ([]*gosec.Issue, int) {
	result := make([]*gosec.Issue, 0)
	trueIssues := 0
	for _, issue := range issues {
		if issue.Severity >= severity && issue.Confidence >= confidence {
			result = append(result, issue)
			if (!issue.NoSec || !*flagShowIgnored) && len(issue.Suppressions) == 0 {
				trueIssues++
			}
		}
	}
	return result, trueIssues
}

func main() {
	// Makes sure some version information is set
	prepareVersionInfo()

	// Setup usage description
	flag.Usage = usage

	// Setup the excluded folders from scan
	flag.Var(&flagDirsExclude, "exclude-dir", "Exclude folder from scan (can be specified multiple times)")
	err := flag.Set("exclude-dir", "vendor")
	if err != nil {
		fmt.Fprintf(os.Stderr, "\nError: failed to exclude the %q directory from scan", "vendor")
	}
	err = flag.Set("exclude-dir", ".git")
	if err != nil {
		fmt.Fprintf(os.Stderr, "\nError: failed to exclude the %q directory from scan", ".git")
	}

	// set for exclude
	flag.Var(&flagRulesExclude, "exclude", "Comma separated list of rules IDs to exclude. (see rule list)")

	// Parse command line arguments
	flag.Parse()

	if *flagVersion {
		fmt.Printf("Version: %s\nGit tag: %s\nBuild date: %s\n", Version, GitTag, BuildDate)
		os.Exit(0)
	}

	// Ensure at least one file was specified
	if flag.NArg() == 0 {
		fmt.Fprintf(os.Stderr, "\nError: FILE [FILE...] or './...' expected\n") //#nosec
		flag.Usage()
		os.Exit(1)
	}

	// Setup logging
	logWriter := os.Stderr
	if *flagLogfile != "" {
		var e error
		logWriter, e = os.Create(*flagLogfile)
		if e != nil {
			flag.Usage()
			log.Fatal(e)
		}
	}

	if *flagQuiet {
		logger = log.New(ioutil.Discard, "", 0)
	} else {
		logger = log.New(logWriter, "[gosec] ", log.LstdFlags)
	}

	failSeverity, err := convertToScore(*flagSeverity)
	if err != nil {
		logger.Fatalf("Invalid severity value: %v", err)
	}

	failConfidence, err := convertToScore(*flagConfidence)
	if err != nil {
		logger.Fatalf("Invalid confidence value: %v", err)
	}

	// Load the analyzer configuration
	config, err := loadConfig(*flagConfig)
	if err != nil {
		logger.Fatal(err)
	}

	// Load enabled rule definitions
	excludeRules, err := config.GetGlobal(gosec.ExcludeRules)
	if err != nil {
		logger.Fatal(err)
	}
	includeRules, err := config.GetGlobal(gosec.IncludeRules)
	if err != nil {
		logger.Fatal(err)
	}

	ruleList := loadRules(includeRules, excludeRules)
	if len(ruleList.Rules) == 0 {
		logger.Fatal("No rules are configured")
	}

	// Create the analyzer
	analyzer := gosec.NewAnalyzer(config, *flagScanTests, *flagExcludeGenerated, *flagTrackSuppressions, *flagConcurrency, logger)
	analyzer.LoadRules(ruleList.RulesInfo())

	excludedDirs := gosec.ExcludedDirsRegExp(flagDirsExclude)
	var packages []string
	for _, path := range flag.Args() {
		pcks, err := gosec.PackagePaths(path, excludedDirs)
		if err != nil {
			logger.Fatal(err)
		}
		packages = append(packages, pcks...)
	}
	if len(packages) == 0 {
		logger.Fatal("No packages found")
	}

	var buildTags []string
	if *flagBuildTags != "" {
		buildTags = strings.Split(*flagBuildTags, ",")
	}

	if err := analyzer.Process(buildTags, packages...); err != nil {
		logger.Fatal(err)
	}

	// Collect the results
	issues, metrics, errors := analyzer.Report()

	// Sort the issue by severity
	if *flagSortIssues {
		sortIssues(issues)
	}

	// Filter the issues by severity and confidence
	var trueIssues int
	issues, trueIssues = filterIssues(issues, failSeverity, failConfidence)
	if metrics.NumFound != trueIssues {
		metrics.NumFound = trueIssues
	}

	// Exit quietly if nothing was found
	if len(issues) == 0 && *flagQuiet {
		os.Exit(0)
	}

	// Create output report
	rootPaths := getRootPaths(flag.Args())

	reportInfo := gosec.NewReportInfo(issues, metrics, errors).WithVersion(Version)

	if *flagOutput == "" || *flagStdOut {
		fileFormat := getPrintedFormat(*flagFormat, *flagVerbose)
		if err := printReport(fileFormat, *flagColor, rootPaths, reportInfo); err != nil {
			logger.Fatal(err)
		}
	}
	if *flagOutput != "" {
		if err := saveReport(*flagOutput, *flagFormat, rootPaths, reportInfo); err != nil {
			logger.Fatal(err)
		}
	}

	// Finalize logging
	logWriter.Close() //#nosec

	// Do we have an issue? If so exit 1 unless NoFail is set
	if (len(issues) > 0 || len(errors) > 0) && !*flagNoFail {
		os.Exit(1)
	}
}
