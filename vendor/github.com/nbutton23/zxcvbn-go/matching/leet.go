package matching

import (
	"github.com/nbutton23/zxcvbn-go/entropy"
	"github.com/nbutton23/zxcvbn-go/match"
	"strings"
)

func l33tMatch(password string) []match.Match {

	substitutions := relevantL33tSubtable(password)

	permutations := getAllPermutationsOfLeetSubstitutions(password, substitutions)

	var matches []match.Match

	for _, permutation := range permutations {
		for _, mather := range DICTIONARY_MATCHERS {
			matches = append(matches, mather(permutation)...)
		}
	}

	for _, match := range matches {
		match.Entropy += entropy.ExtraLeetEntropy(match, password)
		match.DictionaryName = match.DictionaryName + "_3117"
	}

	return matches
}

func getAllPermutationsOfLeetSubstitutions(password string, substitutionsMap map[string][]string) []string {

	var permutations []string

	for index, char := range password {
		for value, splice := range substitutionsMap {
			for _, sub := range splice {
				if string(char) == sub {
					var permutation string
					permutation = password[:index] + value + password[index+1:]

					permutations = append(permutations, permutation)
					if index < len(permutation) {
						tempPermutations := getAllPermutationsOfLeetSubstitutions(permutation[index+1:], substitutionsMap)
						for _, temp := range tempPermutations {
							permutations = append(permutations, permutation[:index+1]+temp)
						}

					}
				}
			}
		}
	}

	return permutations
}

func relevantL33tSubtable(password string) map[string][]string {
	relevantSubs := make(map[string][]string)
	for key, values := range L33T_TABLE.Graph {
		for _, value := range values {
			if strings.Contains(password, value) {
				relevantSubs[key] = append(relevantSubs[key], value)
			}
		}
	}
	return relevantSubs
}
