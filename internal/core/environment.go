package core

import (
	"slices"
	"strings"
)

const (
	// EnvironmentVariable selects the environment.
	EnvironmentVariable = "MSECRETS_ENV"
	// DefaultEnvironment is used when it exists and nothing else is chosen.
	DefaultEnvironment = "development"
)

// EnvironmentChoice is the chosen environment and why: "explicit", "variable", "default", or "only".
type EnvironmentChoice struct {
	Name   string
	Reason string
}

// ChooseEnvironment chooses the environment: the explicit name, then
// MSECRETS_ENV, then "development" when it exists, then the only environment.
func ChooseEnvironment(h Host, document *Document, explicit string) (EnvironmentChoice, error) {
	environments := document.Environments.Keys()
	requested, reason := explicit, "explicit"
	if requested == "" {
		requested, reason = getenv(h, EnvironmentVariable), "variable"
	}

	if requested != "" {
		if !document.Environments.Has(requested) {
			return EnvironmentChoice{}, newError(CodeNotFound, "Environment \"%s\" does not exist%s (environments: %s)", requested, Suggest(requested, environments), orNone(environments))
		}
		return EnvironmentChoice{requested, reason}, nil
	}
	if document.Environments.Has(DefaultEnvironment) {
		return EnvironmentChoice{DefaultEnvironment, "default"}, nil
	}
	if len(environments) == 1 {
		return EnvironmentChoice{environments[0], "only"}, nil
	}
	return EnvironmentChoice{}, newError(CodeUsage, "Choose an environment with --env or %s (environments: %s)", EnvironmentVariable, orNone(environments))
}

func distance(left, right []rune) int {
	previous := make([]int, len(right)+1)
	for j := range previous {
		previous[j] = j
	}
	for i := 1; i <= len(left); i++ {
		diagonal := previous[0]
		previous[0] = i
		for j := 1; j <= len(right); j++ {
			above := previous[j]
			cost := 1
			if left[i-1] == right[j-1] {
				cost = 0
			}
			previous[j] = min(above+1, previous[j-1]+1, diagonal+cost)
			diagonal = above
		}
	}
	return previous[len(right)]
}

// Suggest returns ` (did you mean "X"?)` for the closest candidate, or "".
func Suggest(name string, candidates []string) string {
	limit := max(2, len([]rune(name))/3)
	best, bestScore := "", -1
	lower := []rune(strings.ToLower(name))
	for _, candidate := range slices.Clone(candidates) {
		score := distance(lower, []rune(strings.ToLower(candidate)))
		if score <= limit && (bestScore < 0 || score < bestScore) {
			best, bestScore = candidate, score
		}
	}
	if bestScore < 0 {
		return ""
	}
	return " (did you mean \"" + best + "\"?)"
}
