package matching

import (
	"github.com/nbutton23/zxcvbn-go/adjacency"
	"github.com/nbutton23/zxcvbn-go/frequency"
	"github.com/nbutton23/zxcvbn-go/match"
	"sort"
)

var (
	DICTIONARY_MATCHERS []func(password string) []match.Match
	MATCHERS            []func(password string) []match.Match
	ADJACENCY_GRAPHS    []adjacency.AdjacencyGraph
	L33T_TABLE          adjacency.AdjacencyGraph

	SEQUENCES map[string]string
)

const (
	DATE_RX_YEAR_SUFFIX    string = `((\d{1,2})(\s|-|\/|\\|_|\.)(\d{1,2})(\s|-|\/|\\|_|\.)(19\d{2}|200\d|201\d|\d{2}))`
	DATE_RX_YEAR_PREFIX    string = `((19\d{2}|200\d|201\d|\d{2})(\s|-|/|\\|_|\.)(\d{1,2})(\s|-|/|\\|_|\.)(\d{1,2}))`
	DATE_WITHOUT_SEP_MATCH string = `\d{4,8}`
)

func init() {
	loadFrequencyList()
}

func Omnimatch(password string, userInputs []string) (matches []match.Match) {

	//Can I run into the issue where nil is not equal to nil?
	if DICTIONARY_MATCHERS == nil || ADJACENCY_GRAPHS == nil {
		loadFrequencyList()
	}

	if userInputs != nil {
		userInputMatcher := buildDictMatcher("user_inputs", buildRankedDict(userInputs))
		matches = userInputMatcher(password)
	}

	for _, matcher := range MATCHERS {
		matches = append(matches, matcher(password)...)
	}
	sort.Sort(match.Matches(matches))
	return matches
}

func loadFrequencyList() {

	for n, list := range frequency.FrequencyLists {
		DICTIONARY_MATCHERS = append(DICTIONARY_MATCHERS, buildDictMatcher(n, buildRankedDict(list.List)))
	}

	L33T_TABLE = adjacency.AdjacencyGph["l33t"]

	ADJACENCY_GRAPHS = append(ADJACENCY_GRAPHS, adjacency.AdjacencyGph["qwerty"])
	ADJACENCY_GRAPHS = append(ADJACENCY_GRAPHS, adjacency.AdjacencyGph["dvorak"])
	ADJACENCY_GRAPHS = append(ADJACENCY_GRAPHS, adjacency.AdjacencyGph["keypad"])
	ADJACENCY_GRAPHS = append(ADJACENCY_GRAPHS, adjacency.AdjacencyGph["macKeypad"])

	//l33tFilePath, _ := filepath.Abs("adjacency/L33t.json")
	//L33T_TABLE = adjacency.GetAdjancencyGraphFromFile(l33tFilePath, "l33t")

	SEQUENCES = make(map[string]string)
	SEQUENCES["lower"] = "abcdefghijklmnopqrstuvwxyz"
	SEQUENCES["upper"] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	SEQUENCES["digits"] = "0123456789"

	MATCHERS = append(MATCHERS, DICTIONARY_MATCHERS...)
	MATCHERS = append(MATCHERS, spatialMatch)
	MATCHERS = append(MATCHERS, repeatMatch)
	MATCHERS = append(MATCHERS, sequenceMatch)
	MATCHERS = append(MATCHERS, l33tMatch)
	MATCHERS = append(MATCHERS, dateSepMatcher)
	MATCHERS = append(MATCHERS, dateWithoutSepMatch)

}
