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
	"log"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/GoASTScanner/gas"
	"github.com/GoASTScanner/gas/output"
	"github.com/GoASTScanner/gas/rules"
	"github.com/kisielk/gotool"
)

const (
	usageText = `
GAS - Go AST Scanner

Gas analyzes Go source code to look for common programming mistakes that
can lead to security problems.

USAGE:

	# Check a single package
	$ gas $GOPATH/src/github.com/example/project

	# Check all packages under the current directory and save results in
	# json format.
	$ gas -fmt=json -out=results.json ./...

	# Run a specific set of rules (by default all rules will be run):
	$ gas -include=G101,G203,G401  ./...

	# Run all rules except the provided
	$ gas -exclude=G101 $GOPATH/src/github.com/example/project/...

`
)

var (
	// #nosec flag
	flagIgnoreNoSec = flag.Bool("nosec", false, "Ignores #nosec comments when set")

	// format output
	flagFormat = flag.String("fmt", "text", "Set output format. Valid options are: json, csv, html, or text")

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

	logger *log.Logger
)

// #nosec
func usage() {

	fmt.Fprintln(os.Stderr, usageText)
	fmt.Fprint(os.Stderr, "OPTIONS:\n\n")
	flag.PrintDefaults()
	fmt.Fprint(os.Stderr, "\n\nRULES:\n\n")

	// sorted rule list for eas of reading
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

func loadConfig(configFile string) (gas.Config, error) {
	config := gas.NewConfig()
	if configFile != "" {
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
		including := strings.Split(include, ",")
		filters = append(filters, rules.NewRuleFilter(false, including...))
	}

	if exclude != "" {
		excluding := strings.Split(exclude, ",")
		filters = append(filters, rules.NewRuleFilter(true, excluding...))
	}
	return rules.Generate(filters...)
}

func saveOutput(filename, format string, issues []*gas.Issue, metrics *gas.Metrics) error {
	if filename != "" {
		outfile, err := os.Create(filename)
		if err != nil {
			return err
		}
		defer outfile.Close()
		output.CreateReport(outfile, format, issues, metrics)
	} else {
		output.CreateReport(os.Stdout, format, issues, metrics)
	}
	return nil
}

func main() {

	// Setup usage description
	flag.Usage = usage

	// Parse command line arguments
	flag.Parse()

	// Ensure at least one file was specified
	if flag.NArg() == 0 {
		fmt.Fprintf(os.Stderr, "\nError: FILE [FILE...] or './...' expected\n")
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
	logger = log.New(logWriter, "[gas] ", log.LstdFlags)

	// Load config
	config, err := loadConfig(*flagConfig)
	if err != nil {
		logger.Fatal(err)
	}

	// Load enabled rule definitions
	ruleDefinitions := loadRules(*flagRulesInclude, *flagRulesExclude)

	// Create the analyzer
	analyzer := gas.NewAnalyzer(config, logger)
	analyzer.LoadRules(ruleDefinitions.Builders()...)

	vendor := regexp.MustCompile(`[\\/]vendor([\\/]|$)`)

	// Iterate over packages on the import paths
	for _, pkg := range gotool.ImportPaths(flag.Args()) {

		// Skip vendor directory
		if vendor.MatchString(pkg) {
			continue
		}

		abspath, _ := filepath.Abs(pkg)
		logger.Println("Searching directory:", abspath)
		if err := analyzer.Process(pkg); err != nil {
			logger.Fatal(err)
		}
	}

	// Collect the results
	issues, metrics := analyzer.Report()

	issuesFound := len(issues) > 0
	// Exit quietly if nothing was found
	if !issuesFound && *flagQuiet {
		os.Exit(0)
	}

	// Create output report
	if err := saveOutput(*flagOutput, *flagFormat, issues, metrics); err != nil {
		logger.Fatal(err)
	}

	// Finialize logging
	logWriter.Close()

	// Do we have an issue? If so exit 1
	if issuesFound {
		os.Exit(1)
	}
}
