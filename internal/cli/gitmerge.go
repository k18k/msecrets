package cli

import (
	"crypto/sha256"
	"encoding/hex"
	"reflect"
	"slices"
	"strings"

	"github.com/k18k/msecrets/internal/core"
)

var stateLabels = map[core.CellState]string{
	core.StateOK: "signed", core.StateStale: "signed, needs sync", core.StateInvalid: "INVALID SIGNATURE",
	core.StateUnexpected: "UNEXPECTED", core.StateMissing: "missing", core.StateAbsent: "",
}

func fingerprint(text string) string {
	sum := sha256.Sum256([]byte(text))
	return hex.EncodeToString(sum[:])[:12]
}

func sortedNames(names []string) []string {
	// JavaScript sorts by UTF-16 code units; names are ASCII, so byte order is the same.
	slices.Sort(names)
	return names
}

// renderForDiff is a stable, readable rendering of a secrets file for `git diff`
// (textconv). Ciphertext is reduced to a short fingerprint, so diffs show what
// changed: which values, who signed them, and whether the signatures hold.
func renderForDiff(text string) string {
	document, err := core.ParseDocumentText(text, "")
	if err != nil {
		return "# msecrets: this file is not a valid v4 secrets file\n# " + strings.ReplaceAll(err.Error(), "\n", "\n# ") + "\n" + text
	}

	lines := []string{"# msecrets file " + document.ID, "", "recipients:"}
	for _, name := range sortedNames(document.Recipients.Keys()) {
		key, err := core.RecipientKey(document, name)
		if err != nil {
			continue // unreachable: the document is validated
		}
		entry, _ := document.Recipients.Get(name)
		line := "  " + name + ": " + string(key.Kind)
		if key.SigningKey == nil {
			line += " (read-only)"
		}
		line += " " + fingerprint(key.Token)
		if entry.Description != "" {
			line += " # " + entry.Description
		}
		lines = append(lines, line)
	}

	lines = append(lines, "", "environments:")
	for name, environment := range document.Environments.All() {
		recipients := strings.Join(sortedNames(slices.Clone(environment.Recipients)), ", ")
		if recipients == "" {
			recipients = "(no recipients)"
		}
		lines = append(lines, "  "+name+": "+recipients)
	}

	report, _ := core.Inspect(document)
	lines = append(lines, "", "secrets:")
	for _, name := range sortedNames(document.Secrets.Keys()) {
		secret, _ := document.Secrets.Get(name)
		line := "  " + name + ":"
		if secret.Description != "" {
			line += " # " + secret.Description
		}
		lines = append(lines, line)
		if secret.Environments != nil {
			lines = append(lines, "    only: "+strings.Join(secret.Environments, ", "))
		}
		for _, cell := range report.Cells {
			if cell.Secret != name || cell.State == core.StateAbsent {
				continue
			}
			line := "    " + cell.Environment + ": " + stateLabels[cell.State]
			if cell.Signer != "" {
				line += " by " + cell.Signer
			}
			if value, ok := secret.Values.Get(cell.Environment); ok {
				line += " " + fingerprint(value.Data)
			}
			lines = append(lines, line)
		}
	}
	return strings.Join(lines, "\n") + "\n"
}

// absent marks a key missing on one side of a merge (JSON null is a value).
type absentValue struct{}

var absent any = absentValue{}

func same(left, right any) bool { return reflect.DeepEqual(left, right) }

// isNameSet: paths merged as sets of names rather than atomically.
func isNameSet(path []string) bool {
	return len(path) == 3 && ((path[0] == "environments" && path[2] == "recipients") || (path[0] == "secrets" && path[2] == "environments"))
}

// isAtomic: paths whose values must never be merged field by field.
func isAtomic(path []string) bool {
	return (len(path) == 2 && path[0] == "recipients") || (len(path) == 4 && path[0] == "secrets" && path[2] == "values")
}

func nameList(value any) []string {
	list, _ := value.([]any)
	names := []string{}
	for _, entry := range list {
		if name, ok := entry.(string); ok {
			names = append(names, name)
		}
	}
	return names
}

// mergeNameSets: the union of both sides, minus names that either side removed.
func mergeNameSets(base, ours, theirs any) any {
	baseNames, ourNames, theirNames := nameList(base), nameList(ours), nameList(theirs)
	removed := map[string]bool{}
	for _, name := range baseNames {
		if !slices.Contains(ourNames, name) || !slices.Contains(theirNames, name) {
			removed[name] = true
		}
	}
	merged := []any{}
	seen := map[string]bool{}
	for _, name := range append(ourNames, theirNames...) {
		if !seen[name] && !removed[name] {
			merged = append(merged, name)
		}
		seen[name] = true
	}
	return merged
}

func field(object *core.Map[any], key string) any {
	if object == nil {
		return absent
	}
	if value, ok := object.Get(key); ok {
		return value
	}
	return absent
}

func merge3(base, ours, theirs any, path []string, conflicts *[]string) any {
	switch {
	case same(ours, theirs):
		return ours
	case same(base, ours):
		return theirs
	case same(base, theirs):
		return ours
	}
	if isNameSet(path) {
		_, baseList := base.([]any)
		_, ourList := ours.([]any)
		_, theirList := theirs.([]any)
		// A secret without "environments" applies to every environment; that is not a list to merge.
		if path[0] == "secrets" && !(baseList && ourList && theirList) {
			*conflicts = append(*conflicts, strings.Join(path, "."))
			return ours
		}
		return mergeNameSets(base, ours, theirs)
	}
	ourObject, ourIsObject := ours.(*core.Map[any])
	theirObject, theirIsObject := theirs.(*core.Map[any])
	if !isAtomic(path) && ourIsObject && theirIsObject {
		baseObject, _ := base.(*core.Map[any])
		result := &core.Map[any]{}
		keys := ourObject.Keys()
		for _, key := range theirObject.Keys() {
			if !ourObject.Has(key) {
				keys = append(keys, key)
			}
		}
		for _, key := range keys {
			merged := merge3(field(baseObject, key), field(ourObject, key), field(theirObject, key), append(slices.Clone(path), key), conflicts)
			if merged != absent {
				result.Set(key, merged)
			}
		}
		return result
	}
	location := strings.Join(path, ".")
	if location == "" {
		location = "(file)"
	}
	*conflicts = append(*conflicts, location)
	return ours
}

func parseJSONOrAbsent(text string) any {
	value, err := core.ParseJSON(text)
	if err != nil {
		// An unparsable side (e.g. an empty base for a newly added file) merges as absent.
		return absent
	}
	return value
}

// mergeDocuments is a three-way structural merge of secrets files. Independent
// changes merge cleanly; changes to the same value conflict and keep "ours".
func mergeDocuments(baseText, oursText, theirsText string) (string, []string) {
	conflicts := []string{}
	merged := merge3(parseJSONOrAbsent(baseText), parseJSONOrAbsent(oursText), parseJSONOrAbsent(theirsText), []string{}, &conflicts)
	if merged == absent {
		merged = nil
	}
	document, issues := core.ValidateDocument(merged)
	if document == nil {
		for _, issue := range issues {
			conflicts = append(conflicts, issue.Path+": "+issue.Message)
		}
		return oursText, conflicts
	}
	return core.SerializeDocument(document), conflicts
}
