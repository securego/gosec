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
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/kisielk/gotool"
	"github.com/securego/gosec"
	"github.com/securego/gosec/output"
	"github.com/securego/gosec/rules"
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

var (
	// #nosec flag
	flagIgnoreNoSec = flag.Bool("nosec", false, "Ignores #nosec comments when set")

	// format output
	flagFormat = flag.String("fmt", "text", "Set output format. Valid options are: json, yaml, csv, junit-xml, html, or text")

	// output file
	flagOutput = flag.String("out", "", "Set output file for results")

	// config file
	flagConfig = flag.String("conf", "", "Path to optional config file")

	// quiet
	flagQuiet = flag.Bool("quiet", false, "Only show output when errors are found")

	// rules to explicitly include
	flagRulesInclude = flag.String("include", "", "Comma separated list of rules IDs to include. (see rule list)")

	// rules to explicitly exclude
	flagRulesExclude = flag.String("exclude", "", "Comma separated list of rules IDs to exclude. (see rule list)")

	// log to file or stderr
	flagLogfile = flag.String("log", "", "Log messages to file rather than stderr")

	// sort the issues by severity
	flagSortIssues = flag.Bool("sort", true, "Sort issues by severity")

	// go build tags
	flagBuildTags = flag.String("tags", "", "Comma separated list of build tags")

	logger *log.Logger
)

// #nosec
func usage() {

	usageText := fmt.Sprintf(usageText, Version, GitTag, BuildDate)
	fmt.Fprintln(os.Stderr, usageText)
	fmt.Fprint(os.Stderr, "OPTIONS:\n\n")
	flag.PrintDefaults()
	fmt.Fprint(os.Stderr, "\n\nRULES:\n\n")

	// sorted rule list for ease of reading
	rl := rules.Generate()
	keys := make([]string, 0, len(rl))
	for key := range rl {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, k := range keys {
		v := rl[k]
		fmt.Fprintf(os.Stderr, "\t%s: %s\n", k, v.Description)
	}
	fmt.Fprint(os.Stderr, "\n")
}

func loadConfig(configFile string) (gosec.Config, error) {
	config := gosec.NewConfig()
	if configFile != "" {
		// #nosec
		file, err := os.Open(configFile)
		if err != nil {
			return nil, err
		}
		defer file.Close()
		if _, err := config.ReadFrom(file); err != nil {
			return nil, err
		}
	}
	if *flagIgnoreNoSec {
		config.SetGlobal("nosec", "true")
	}
	return config, nil
}

func loadRules(include, exclude string) rules.RuleList {
	var filters []rules.RuleFilter
	if include != "" {
		logger.Printf("including rules: %s", include)
		including := strings.Split(include, ",")
		filters = append(filters, rules.NewRuleFilter(false, including...))
	} else {
		logger.Println("including rules: default")
	}

	if exclude != "" {
		logger.Printf("excluding rules: %s", exclude)
		excluding := strings.Split(exclude, ",")
		filters = append(filters, rules.NewRuleFilter(true, excluding...))
	} else {
		logger.Println("excluding rules: default")
	}
	return rules.Generate(filters...)
}

func saveOutput(filename, format string, issues []*gosec.Issue, metrics *gosec.Metrics) error {
	if filename != "" {
		outfile, err := os.Create(filename)
		if err != nil {
			return err
		}
		defer outfile.Close()
		err = output.CreateReport(outfile, format, issues, metrics)
		if err != nil {
			return err
		}
	} else {
		err := output.CreateReport(os.Stdout, format, issues, metrics)
		if err != nil {
			return err
		}
	}
	return nil
}

func cleanPath(path string) (string, error) {
	cleanFailed := fmt.Errorf("%s is not within the $GOPATH and cannot be processed", path)
	nonRecursivePath := strings.TrimSuffix(path, "/...")
	// do not attempt to clean directs that are resolvable on gopath
	if _, err := os.Stat(nonRecursivePath); err != nil && os.IsNotExist(err) {
		log.Printf("directory %s doesn't exist, checking if is a package on $GOPATH", path)
		for _, basedir := range gosec.Gopath() {
			dir := filepath.Join(basedir, "src", nonRecursivePath)
			if st, err := os.Stat(dir); err == nil && st.IsDir() {
				log.Printf("located %s in %s", path, dir)
				return path, nil
			}
		}
		return "", cleanFailed
	}

	// ensure we resolve package directory correctly based on $GOPATH
	pkgPath, err := gosec.GetPkgRelativePath(path)
	if err != nil {
		return "", cleanFailed
	}
	return pkgPath, nil
}

func cleanPaths(paths []string) []string {
	var clean []string
	for _, path := range paths {
		cleaned, err := cleanPath(path)
		if err != nil {
			log.Fatal(err)
		}
		clean = append(clean, cleaned)
	}
	return clean
}

func resolvePackage(pkg string, searchPaths []string) string {
	for _, basedir := range searchPaths {
		dir := filepath.Join(basedir, "src", pkg)
		if st, err := os.Stat(dir); err == nil && st.IsDir() {
			return dir
		}
	}
	return pkg
}

func main() {

	// Setup usage description
	flag.Usage = usage

	// Parse command line arguments
	flag.Parse()

	// Ensure at least one file was specified
	if flag.NArg() == 0 {
		fmt.Fprintf(os.Stderr, "\nError: FILE [FILE...] or './...' expected\n") // #nosec
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

	// Load config
	config, err := loadConfig(*flagConfig)
	if err != nil {
		logger.Fatal(err)
	}

	// Load enabled rule definitions
	ruleDefinitions := loadRules(*flagRulesInclude, *flagRulesExclude)
	if len(ruleDefinitions) <= 0 {
		logger.Fatal("cannot continue: no rules are configured.")
	}

	// Create the analyzer
	analyzer := gosec.NewAnalyzer(config, logger)
	analyzer.LoadRules(ruleDefinitions.Builders())

	vendor := regexp.MustCompile(`[\\/]vendor([\\/]|$)`)

	var packages []string
	// Iterate over packages on the import paths
	gopaths := gosec.Gopath()
	for _, pkg := range gotool.ImportPaths(cleanPaths(flag.Args())) {

		// Skip vendor directory
		if vendor.MatchString(pkg) {
			continue
		}
		packages = append(packages, resolvePackage(pkg, gopaths))
	}

	var buildTags []string
	if *flagBuildTags != "" {
		buildTags = strings.Split(*flagBuildTags, ",")
	}
	if err := analyzer.Process(buildTags, packages...); err != nil {
		logger.Fatal(err)
	}

	// Collect the results
	issues, metrics := analyzer.Report()

	issuesFound := len(issues) > 0
	// Exit quietly if nothing was found
	if !issuesFound && *flagQuiet {
		os.Exit(0)
	}

	// Sort the issue by severity
	if *flagSortIssues {
		sortIssues(issues)
	}

	// Create output report
	if err := saveOutput(*flagOutput, *flagFormat, issues, metrics); err != nil {
		logger.Fatal(err)
	}

	// Finialize logging
	logWriter.Close() // #nosec

	// Do we have an issue? If so exit 1
	if issuesFound {
		os.Exit(1)
	}
}
