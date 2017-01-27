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
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"

	gas "github.com/GoASTScanner/gas/core"
	"github.com/GoASTScanner/gas/output"
)

type recursion bool

const (
	recurse   recursion = true
	noRecurse recursion = false
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

	usageText = `
GAS - Go AST Scanner

Gas analyzes Go source code to look for common programming mistakes that
can lead to security problems.

USAGE:

	# Check a single Go file
	$ gas example.go

	# Check all files under the current directory and save results in
	# json format.
	$ gas -fmt=json -out=results.json ./...

	# Run a specific set of rules (by default all rules will be run):
	$ gas -include=G101,G203,G401 ./...

	# Run all rules except the provided
	$ gas -exclude=G101 ./...

`

	logger *log.Logger
)

func extendConfList(conf map[string]interface{}, name string, inputStr string) {
	if inputStr == "" {
		conf[name] = []string{}
	} else {
		input := strings.Split(inputStr, ",")
		if val, ok := conf[name]; ok {
			if data, ok := val.(*[]string); ok {
				conf[name] = append(*data, input...)
			} else {
				logger.Fatal("Config item must be a string list: ", name)
			}
		} else {
			conf[name] = input
		}
	}
}

func buildConfig(incRules string, excRules string) map[string]interface{} {
	config := make(map[string]interface{})
	if flagConfig != nil && *flagConfig != "" { // parse config if we have one
		if data, err := ioutil.ReadFile(*flagConfig); err == nil {
			if err := json.Unmarshal(data, &(config)); err != nil {
				logger.Fatal("Could not parse JSON config: ", *flagConfig, ": ", err)
			}
		} else {
			logger.Fatal("Could not read config file: ", *flagConfig)
		}
	}

	// add in CLI include and exclude data
	extendConfList(config, "include", incRules)
	extendConfList(config, "exclude", excRules)

	// override ignoreNosec if given on CLI
	if flagIgnoreNoSec != nil {
		config["ignoreNosec"] = *flagIgnoreNoSec
	} else {
		val, ok := config["ignoreNosec"]
		if !ok {
			config["ignoreNosec"] = false
		} else if _, ok := val.(bool); !ok {
			logger.Fatal("Config value must be a bool: 'ignoreNosec'")
		}
	}

	return config
}

// #nosec
func usage() {

	fmt.Fprintln(os.Stderr, usageText)
	fmt.Fprint(os.Stderr, "OPTIONS:\n\n")
	flag.PrintDefaults()
	fmt.Fprint(os.Stderr, "\n\nRULES:\n\n")

	// sorted rule list for eas of reading
	rl := GetFullRuleList()
	keys := make([]string, 0, len(rl))
	for key := range rl {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, k := range keys {
		v := rl[k]
		fmt.Fprintf(os.Stderr, "\t%s: %s\n", k, v.description)
	}
	fmt.Fprint(os.Stderr, "\n")
}

func main() {

	// Setup usage description
	flag.Usage = usage

	//  Exclude files
	excluded := newFileList("*_test.go")
	flag.Var(excluded, "skip", "File pattern to exclude from scan. Uses simple * globs and requires full match")

	incRules := ""
	flag.StringVar(&incRules, "include", "", "Comma separated list of rules IDs to include. (see rule list)")

	excRules := ""
	flag.StringVar(&excRules, "exclude", "", "Comma separated list of rules IDs to exclude. (see rule list)")

	// Custom commands / utilities to run instead of default analyzer
	tools := newUtils()
	flag.Var(tools, "tool", "GAS utilities to assist with rule development")

	// Setup logging
	logger = log.New(os.Stderr, "[gas] ", log.LstdFlags)

	// Parse command line arguments
	flag.Parse()

	// Ensure at least one file was specified
	if flag.NArg() == 0 {

		fmt.Fprintf(os.Stderr, "\nError: FILE [FILE...] or './...' expected\n")
		flag.Usage()
		os.Exit(1)
	}

	// Run utils instead of analysis
	if len(tools.call) > 0 {
		tools.run(flag.Args()...)
		os.Exit(0)
	}

	// Setup analyzer
	config := buildConfig(incRules, excRules)
	analyzer := gas.NewAnalyzer(config, logger)
	AddRules(&analyzer, config)

	toAnalyze := getFilesToAnalyze(flag.Args(), excluded)

	for _, file := range toAnalyze {
		logger.Printf(`Processing "%s"...`, file)
		if err := analyzer.Process(file); err != nil {
			logger.Printf(`Failed to process: "%s"`, file)
			logger.Println(err)
			logger.Fatalf(`Halting execution.`)
		}
	}

	issuesFound := len(analyzer.Issues) > 0
	// Exit quietly if nothing was found
	if !issuesFound && *flagQuiet {
		os.Exit(0)
	}

	// Create output report
	if *flagOutput != "" {
		outfile, err := os.Create(*flagOutput)
		if err != nil {
			logger.Fatalf("Couldn't open: %s for writing. Reason - %s", *flagOutput, err)
		}
		defer outfile.Close()
		output.CreateReport(outfile, *flagFormat, &analyzer)
	} else {
		output.CreateReport(os.Stdout, *flagFormat, &analyzer)
	}

	// Do we have an issue? If so exit 1
	if issuesFound {
		os.Exit(1)
	}
}

// getFilesToAnalyze lists all files
func getFilesToAnalyze(paths []string, excluded *fileList) []string {
	//log.Println("getFilesToAnalyze: start")
	var toAnalyze []string
	for _, relativePath := range paths {
		//log.Printf("getFilesToAnalyze: processing \"%s\"\n", path)
		// get the absolute path before doing anything else
		path, err := filepath.Abs(relativePath)
		if err != nil {
			log.Fatal(err)
		}
		if filepath.Base(relativePath) == "..." {
			toAnalyze = append(
				toAnalyze,
				listFiles(filepath.Dir(path), recurse, excluded)...,
			)
		} else {
			var (
				finfo os.FileInfo
				err   error
			)
			if finfo, err = os.Stat(path); err != nil {
				logger.Fatal(err)
			}
			if !finfo.IsDir() {
				if shouldInclude(path, excluded) {
					toAnalyze = append(toAnalyze, path)
				}
			} else {
				toAnalyze = listFiles(path, noRecurse, excluded)
			}
		}
	}
	//log.Println("getFilesToAnalyze: end")
	return toAnalyze
}

// listFiles returns a list of all files found that pass the shouldInclude check.
// If doRecursiveWalk it true, it will walk the tree rooted at absPath, otherwise it
// will only include files directly within the dir referenced by absPath.
func listFiles(absPath string, doRecursiveWalk recursion, excluded *fileList) []string {
	var files []string

	walk := func(path string, info os.FileInfo, err error) error {
		if info.IsDir() && doRecursiveWalk == noRecurse {
			return filepath.SkipDir
		}
		if shouldInclude(path, excluded) {
			files = append(files, path)
		}
		return nil
	}

	if err := filepath.Walk(absPath, walk); err != nil {
		log.Fatal(err)
	}
	return files
}

// shouldInclude checks if a specific path which is expected to reference
// a regular file should be included
func shouldInclude(path string, excluded *fileList) bool {
	return filepath.Ext(path) == ".go" && !excluded.Contains(path)
}
