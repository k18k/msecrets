package core

// Inspection of a secrets document: completeness, recipient drift, signatures,
// and access configuration. Needs public data only, so it runs anywhere (CI).

import (
	"fmt"
	"slices"
)

// CellState is the state of one secret in one environment.
type CellState string

// Cell states.
const (
	// StateOK: signed, current, and encrypted to the environment's current recipients.
	StateOK CellState = "ok"
	// StateStale: valid, but encrypted to an outdated recipient set; `msecrets sync` fixes it.
	StateStale CellState = "stale"
	// StateMissing: the secret applies to the environment but has no value there.
	StateMissing CellState = "missing"
	// StateInvalid: the signature does not verify; the value must not be trusted.
	StateInvalid CellState = "invalid"
	// StateUnexpected: a value exists in an environment the secret does not apply to.
	StateUnexpected CellState = "unexpected"
	// StateAbsent: no value, and none expected.
	StateAbsent CellState = "absent"
)

// Cell is the state of one secret in one environment.
type Cell struct {
	Secret      string
	Environment string
	State       CellState
	// Signer is the recipient that signed the value ("" if there is none).
	Signer string
	// Detail explains an invalid signature.
	Detail string
}

// FindingLevel is "error" or "warning".
type FindingLevel string

// Finding levels.
const (
	LevelError   FindingLevel = "error"
	LevelWarning FindingLevel = "warning"
)

// Finding is a problem reported by [Inspect]. Secret, Environment, and Recipient are "" when not applicable.
type Finding struct {
	Level       FindingLevel
	Message     string
	Secret      string
	Environment string
	Recipient   string
}

// Report is the result of [Inspect].
type Report struct {
	Cells    []Cell
	Findings []Finding
	// OK is true when there are no errors: every value is present, current, and signed.
	OK bool
}

// InspectCell returns the state of a secret in an environment.
func InspectCell(document *Document, secretName, environment string) (Cell, error) {
	cell := Cell{Secret: secretName, Environment: environment}
	secret, exists := document.Secrets.Get(secretName)
	var value *SealedValue
	expected := false
	if exists {
		value, _ = secret.Values.Get(environment)
		expected = slices.Contains(SecretEnvironments(document, secret), environment)
	}

	if value == nil {
		cell.State = StateAbsent
		if expected {
			cell.State = StateMissing
		}
		return cell, nil
	}
	cell.Signer = value.By
	if !expected {
		cell.State = StateUnexpected
		return cell, nil
	}

	problem, err := SignatureProblem(document, secretName, environment, value)
	if err != nil {
		return Cell{}, err
	}
	if problem != "" {
		cell.State, cell.Detail = StateInvalid, problem
		return cell, nil
	}
	digest, err := EnvironmentDigest(document, environment)
	if err != nil {
		return Cell{}, err
	}
	cell.State = StateStale
	if value.To == digest {
		cell.State = StateOK
	}
	return cell, nil
}

func cellFinding(cell Cell) string {
	switch cell.State {
	case StateMissing:
		return fmt.Sprintf("%s has no value in \"%s\"", cell.Secret, cell.Environment)
	case StateStale:
		return fmt.Sprintf("%s in \"%s\" is encrypted to an outdated recipient set; run `msecrets sync`", cell.Secret, cell.Environment)
	case StateInvalid:
		return fmt.Sprintf("%s in \"%s\" has an invalid signature: %s", cell.Secret, cell.Environment, cell.Detail)
	case StateUnexpected:
		return fmt.Sprintf("%s has a value in \"%s\", which it does not apply to; remove it with `msecrets unset %s --env %s`", cell.Secret, cell.Environment, cell.Secret, cell.Environment)
	}
	return ""
}

// Inspect checks every cell of the document and its access configuration.
func Inspect(document *Document) (Report, error) {
	report := Report{Cells: []Cell{}, Findings: []Finding{}}
	environments := document.Environments.Keys()
	for _, secret := range document.Secrets.keys {
		for _, environment := range environments {
			cell, err := InspectCell(document, secret, environment)
			if err != nil {
				return Report{}, err
			}
			report.Cells = append(report.Cells, cell)
		}
	}
	for _, cell := range report.Cells {
		if message := cellFinding(cell); message != "" {
			report.Findings = append(report.Findings, Finding{Level: LevelError, Message: message, Secret: cell.Secret, Environment: cell.Environment})
		}
	}

	used := map[string]bool{}
	for _, environment := range environments {
		keys, err := environmentKeys(document, environment)
		if err != nil {
			return Report{}, err
		}
		entry, _ := document.Environments.Get(environment)
		for _, name := range entry.Recipients {
			used[name] = true
		}
		warn := func(format string) {
			report.Findings = append(report.Findings, Finding{Level: LevelWarning, Environment: environment, Message: fmt.Sprintf(format, environment)})
		}
		signing := slices.ContainsFunc(keys, func(key *PublicKey) bool { return key.SigningKey != nil })
		if len(keys) == 0 {
			warn("Environment \"%s\" has no recipients, so it cannot hold values")
		} else if !signing {
			warn("Nobody can write to \"%s\": none of its recipients has a signing key (msecrets1… or ssh-ed25519)")
		}
		postQuantum := func(key *PublicKey) bool { return key.PostQuantum }
		classical := func(key *PublicKey) bool { return !key.PostQuantum }
		if slices.ContainsFunc(keys, postQuantum) && slices.ContainsFunc(keys, classical) {
			warn("\"%s\" mixes post-quantum and classical recipients, so its values are only as strong as classical X25519")
		}
	}

	for _, recipient := range document.Recipients.keys {
		if !used[recipient] {
			report.Findings = append(report.Findings, Finding{Level: LevelWarning, Recipient: recipient, Message: fmt.Sprintf("Recipient \"%s\" has no access to any environment", recipient)})
		}
	}

	report.OK = !slices.ContainsFunc(report.Findings, func(finding Finding) bool { return finding.Level == LevelError })
	return report, nil
}
