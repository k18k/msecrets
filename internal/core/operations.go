package core

// Mutations of a secrets document. Each operation mutates the document it is
// given; callers run them on a copy (see UpdateDocumentFile) so an error leaves
// the file untouched.

import (
	"bytes"
	"slices"
	"strings"
	"unicode/utf8"
)

// Slot is a secret in an environment.
type Slot struct {
	Secret      string
	Environment string
}

// SkippedSlot is a slot an operation could not re-encrypt, and why.
type SkippedSlot struct {
	Slot
	Reason string
}

// SyncResult reports re-encrypted and skipped slots.
type SyncResult struct {
	Updated []Slot
	Skipped []SkippedSlot
}

// RevokeResult is the result of revoking access.
type RevokeResult struct {
	SyncResult
	// Rotate lists the values the recipient could read; rotate them, since copies may exist.
	Rotate []Slot
}

// RequireSecret returns a secret or a NOT_FOUND error.
func RequireSecret(document *Document, name string) (*SecretEntry, error) {
	secret, ok := document.Secrets.Get(name)
	if !ok {
		return nil, newError(CodeNotFound, "Secret %s does not exist", name)
	}
	return secret, nil
}

// RequireEnvironment returns an environment or a NOT_FOUND error.
func RequireEnvironment(document *Document, name string) (*EnvironmentEntry, error) {
	environment, ok := document.Environments.Get(name)
	if !ok {
		return nil, newError(CodeNotFound, "Environment \"%s\" does not exist (environments: %s)", name, orNone(document.Environments.keys))
	}
	return environment, nil
}

// RequireRecipient returns a recipient or a NOT_FOUND error.
func RequireRecipient(document *Document, name string) (*RecipientEntry, error) {
	recipient, ok := document.Recipients.Get(name)
	if !ok {
		return nil, newError(CodeNotFound, "Recipient \"%s\" does not exist", name)
	}
	return recipient, nil
}

type slotValue struct {
	Slot
	value *SealedValue
}

func slots(document *Document, filter func(Slot) bool) []slotValue {
	var result []slotValue
	for secretName, secret := range document.Secrets.All() {
		for environment, value := range secret.Values.All() {
			slot := Slot{secretName, environment}
			if filter == nil || filter(slot) {
				result = append(result, slotValue{slot, value})
			}
		}
	}
	return result
}

func slotList(targets []slotValue) []Slot {
	list := make([]Slot, len(targets))
	for index, target := range targets {
		list[index] = target.Slot
	}
	return list
}

func requireValidSignatures(document *Document, targets []slotValue) error {
	for _, target := range targets {
		problem, err := SignatureProblem(document, target.Secret, target.Environment, target.value)
		if err != nil {
			return err
		}
		if problem != "" {
			return newError(CodeSignature, "Refusing to re-sign %s in \"%s\": %s. Set a new value with `msecrets set %s --env %s`",
				target.Secret, target.Environment, problem, target.Secret, target.Environment)
		}
	}
	return nil
}

func requireUniqueKey(document *Document, publicKey *PublicKey, except string) error {
	for _, other := range document.Recipients.keys {
		key, err := RecipientKey(document, other)
		if err != nil {
			return err
		}
		if other != except && bytes.Equal(key.EncryptionKey, publicKey.EncryptionKey) {
			return newError(CodeConflict, "This key already belongs to recipient \"%s\"", other)
		}
	}
	return nil
}

// Recipients

// AddRecipient adds a recipient with a public key and an optional description.
func AddRecipient(document *Document, name, key, description string) (*RecipientEntry, error) {
	if err := RequireName(RecipientName, name); err != nil {
		return nil, err
	}
	if document.Recipients.Has(name) {
		return nil, newError(CodeConflict, "Recipient \"%s\" already exists", name)
	}
	publicKey, err := ParsePublicKey(key)
	if err != nil {
		return nil, err
	}
	if err := requireUniqueKey(document, publicKey, ""); err != nil {
		return nil, err
	}
	text, err := NormalizeDescription(description)
	if err != nil {
		return nil, err
	}
	entry := &RecipientEntry{Key: publicKey.Token, Description: text}
	document.Recipients.Set(name, entry)
	return entry, nil
}

// DescribeRecipient sets or (with "") removes the description of a recipient.
func DescribeRecipient(document *Document, name, description string) error {
	entry, err := RequireRecipient(document, name)
	if err != nil {
		return err
	}
	text, err := NormalizeDescription(description)
	if err != nil {
		return err
	}
	entry.Description = text
	return nil
}

// RenameRecipient renames a recipient everywhere; signatures stay valid.
func RenameRecipient(document *Document, from, to string) error {
	if _, err := RequireRecipient(document, from); err != nil {
		return err
	}
	if err := RequireName(RecipientName, to); err != nil {
		return err
	}
	if from == to {
		return nil
	}
	if document.Recipients.Has(to) {
		return newError(CodeConflict, "Recipient \"%s\" already exists", to)
	}
	document.Recipients.Rename(from, to)
	for _, environment := range document.Environments.Values() {
		for index, name := range environment.Recipients {
			if name == from {
				environment.Recipients[index] = to
			}
		}
	}
	for _, slot := range slots(document, nil) {
		if slot.value.By == from {
			slot.value.By = to
		}
	}
	return nil
}

// GrantAccess grants a recipient access to environments and re-encrypts their
// values when possible. Values that cannot be re-encrypted yet stay stale (reported).
func GrantAccess(document *Document, identities []*Identity, recipient string, environments []string) (SyncResult, error) {
	if _, err := RequireRecipient(document, recipient); err != nil {
		return SyncResult{}, err
	}
	for _, name := range environments {
		environment, err := RequireEnvironment(document, name)
		if err != nil {
			return SyncResult{}, err
		}
		if !slices.Contains(environment.Recipients, recipient) {
			environment.Recipients = append(environment.Recipients, recipient)
		}
	}
	if environments == nil {
		environments = []string{}
	}
	return Sync(document, identities, environments)
}

func skippedLines(skipped []SkippedSlot) string {
	lines := make([]string, len(skipped))
	for index, slot := range skipped {
		lines[index] = "  " + slot.Secret + " in \"" + slot.Environment + "\": " + slot.Reason
	}
	return strings.Join(lines, "\n")
}

// RevokeAccess revokes access and re-encrypts every affected value without the
// recipient. It fails when some values cannot be re-encrypted, since the
// revocation would otherwise not take effect, unless allowIncomplete is set.
func RevokeAccess(document *Document, identities []*Identity, recipient string, environments []string, allowIncomplete bool) (RevokeResult, error) {
	if _, err := RequireRecipient(document, recipient); err != nil {
		return RevokeResult{}, err
	}
	var affected []string
	for _, name := range environments {
		environment, err := RequireEnvironment(document, name)
		if err != nil {
			return RevokeResult{}, err
		}
		if slices.Contains(environment.Recipients, recipient) {
			affected = append(affected, name)
		}
	}
	inAffected := func(slot Slot) bool { return slices.Contains(affected, slot.Environment) }

	for _, name := range affected {
		environment, _ := document.Environments.Get(name)
		remaining := slices.DeleteFunc(slices.Clone(environment.Recipients), func(other string) bool { return other == recipient })
		if len(remaining) == 0 && len(slots(document, func(slot Slot) bool { return slot.Environment == name })) > 0 {
			return RevokeResult{}, newError(CodeConflict, "Cannot revoke the last recipient of \"%s\" while it holds values; grant someone else access first", name)
		}
	}

	result, err := resealSlots(document, identities, slots(document, inAffected), func() {
		for _, name := range affected {
			environment, _ := document.Environments.Get(name)
			environment.Recipients = slices.DeleteFunc(environment.Recipients, func(other string) bool { return other == recipient })
		}
	})
	if err != nil {
		return RevokeResult{}, err
	}
	if len(result.Skipped) > 0 && !allowIncomplete {
		return RevokeResult{}, newError(CodeAccessDenied, "Revoking \"%s\" requires re-encrypting values you cannot decrypt or sign:\n%s", recipient, skippedLines(result.Skipped))
	}
	return RevokeResult{SyncResult: result, Rotate: slotList(slots(document, inAffected))}, nil
}

// RemoveRecipient removes a recipient from every environment and from the file.
func RemoveRecipient(document *Document, identities []*Identity, name string) (RevokeResult, error) {
	result, err := RevokeAccess(document, identities, name, document.Environments.Keys(), false)
	if err != nil {
		return RevokeResult{}, err
	}
	signed := slots(document, nil)
	signed = slices.DeleteFunc(signed, func(slot slotValue) bool { return slot.value.By != name })
	if len(signed) > 0 {
		lines := make([]string, len(signed))
		for index, slot := range signed {
			lines[index] = "  " + slot.Secret + " in \"" + slot.Environment + "\""
		}
		return RevokeResult{}, newError(CodeAccessDenied, "Cannot remove \"%s\": these values are still signed by them and must be set again first:\n%s", name, strings.Join(lines, "\n"))
	}
	document.Recipients.Delete(name)
	return result, nil
}

// ReplaceRecipientKey replaces the key of a recipient (key rotation or recovery).
// Every value readable by the recipient is decrypted first, then re-encrypted to
// the new key and re-signed, so it requires access to all of them.
func ReplaceRecipientKey(document *Document, identities []*Identity, name, key string) ([]Slot, error) {
	entry, err := RequireRecipient(document, name)
	if err != nil {
		return nil, err
	}
	publicKey, err := ParsePublicKey(key)
	if err != nil {
		return nil, err
	}
	if err := requireUniqueKey(document, publicKey, name); err != nil {
		return nil, err
	}

	var environments []string
	for environment, entry := range document.Environments.All() {
		if slices.Contains(entry.Recipients, name) {
			environments = append(environments, environment)
		}
	}
	targets := slots(document, func(slot Slot) bool { return slices.Contains(environments, slot.Environment) })
	result, err := resealSlots(document, identities, targets, func() { entry.Key = publicKey.Token })
	if err != nil {
		return nil, err
	}
	if len(result.Skipped) > 0 {
		return nil, newError(CodeAccessDenied, "Rotating the key of \"%s\" requires re-encrypting values you cannot decrypt or sign (to rotate your own key, load the new identity too):\n%s", name, skippedLines(result.Skipped))
	}
	return result.Updated, nil
}

// Environments

// AddEnvironment adds an environment readable by the given recipients.
func AddEnvironment(document *Document, name string, recipients []string) error {
	if err := RequireName(EnvironmentName, name); err != nil {
		return err
	}
	if document.Environments.Has(name) {
		return newError(CodeConflict, "Environment \"%s\" already exists", name)
	}
	unique := []string{}
	for _, recipient := range recipients {
		if _, err := RequireRecipient(document, recipient); err != nil {
			return err
		}
		if !slices.Contains(unique, recipient) {
			unique = append(unique, recipient)
		}
	}
	document.Environments.Set(name, &EnvironmentEntry{Recipients: unique})
	return nil
}

// RenameEnvironment renames an environment, keeping its position, and re-signs its values.
func RenameEnvironment(document *Document, identities []*Identity, from, to string) error {
	if _, err := RequireEnvironment(document, from); err != nil {
		return err
	}
	if err := RequireName(EnvironmentName, to); err != nil {
		return err
	}
	if from == to {
		return nil
	}
	if document.Environments.Has(to) {
		return newError(CodeConflict, "Environment \"%s\" already exists", to)
	}

	affected := slots(document, func(slot Slot) bool { return slot.Environment == from })
	if err := requireValidSignatures(document, affected); err != nil {
		return err
	}

	document.Environments.Rename(from, to)
	for _, secret := range document.Secrets.Values() {
		for index, name := range secret.Environments {
			if name == from {
				secret.Environments[index] = to
			}
		}
		secret.Values.Rename(from, to)
	}

	if len(affected) > 0 {
		signer, err := SignerFor(document, identities, to, "")
		if err != nil {
			return err
		}
		for _, slot := range affected {
			secret, _ := document.Secrets.Get(slot.Secret)
			secret.Values.Set(to, ResignValue(document, slot.Secret, to, slot.value, signer))
		}
	}
	return nil
}

// RemoveEnvironment deletes an environment, its values, and secrets scoped only to it.
func RemoveEnvironment(document *Document, name string) (removedValues []Slot, removedSecrets []string, err error) {
	if _, err := RequireEnvironment(document, name); err != nil {
		return nil, nil, err
	}
	removedValues = slotList(slots(document, func(slot Slot) bool { return slot.Environment == name }))
	removedSecrets = []string{}

	document.Environments.Delete(name)
	for secretName, secret := range document.Secrets.All() {
		secret.Values.Delete(name)
		if secret.Environments != nil {
			secret.Environments = slices.DeleteFunc(secret.Environments, func(environment string) bool { return environment == name })
			if len(secret.Environments) == 0 {
				document.Secrets.Delete(secretName)
				removedSecrets = append(removedSecrets, secretName)
			}
		}
	}
	return removedValues, removedSecrets, nil
}

// Secrets and values

// SetValueInput describes a value to set.
type SetValueInput struct {
	Secret      string
	Environment string
	Value       string
	// As signs as this recipient instead of the first eligible one ("" for any).
	As string
}

// SetValue encrypts and signs a value, creating the secret if needed.
func SetValue(document *Document, identities []*Identity, input SetValueInput) (*SealedValue, error) {
	if err := RequireName(SecretName, input.Secret); err != nil {
		return nil, err
	}
	if _, err := RequireEnvironment(document, input.Environment); err != nil {
		return nil, err
	}
	if strings.Contains(input.Value, "\x00") {
		return nil, newError(CodeUsage, "Secret values cannot contain NUL characters")
	}
	if !utf8.ValidString(input.Value) {
		return nil, newError(CodeUsage, "Secret values must be valid UTF-8")
	}

	existing, exists := document.Secrets.Get(input.Secret)
	if exists && !slices.Contains(SecretEnvironments(document, existing), input.Environment) {
		return nil, newError(CodeUsage, "%s does not apply to \"%s\" (it is limited to %s); change that with `msecrets scope`",
			input.Secret, input.Environment, strings.Join(existing.Environments, ", "))
	}

	signer, err := SignerFor(document, identities, input.Environment, input.As)
	if err != nil {
		return nil, err
	}
	sealed, err := SealValue(document, input.Secret, input.Environment, []byte(input.Value), signer)
	if err != nil {
		return nil, err
	}
	if !exists {
		existing = &SecretEntry{}
		document.Secrets.Set(input.Secret, existing)
	}
	existing.Values.Set(input.Environment, sealed)
	return sealed, nil
}

// RevealValue verifies and decrypts a value.
func RevealValue(document *Document, identities []*Identity, secret, environment string) (string, error) {
	entry, err := RequireSecret(document, secret)
	if err != nil {
		return "", err
	}
	if _, err := RequireEnvironment(document, environment); err != nil {
		return "", err
	}
	value, ok := entry.Values.Get(environment)
	if !ok {
		return "", newError(CodeNotFound, "%s has no value in \"%s\"", secret, environment)
	}
	plaintext, err := OpenValue(document, secret, environment, value, identities)
	if err != nil {
		return "", err
	}
	defer clear(plaintext)
	return string(plaintext), nil
}

// UnsetValue removes a value and reports whether it existed.
func UnsetValue(document *Document, secret, environment string) (bool, error) {
	entry, err := RequireSecret(document, secret)
	if err != nil {
		return false, err
	}
	if _, err := RequireEnvironment(document, environment); err != nil {
		return false, err
	}
	return entry.Values.Delete(environment), nil
}

// CreateSecret creates a secret without values. Environments nil means every environment.
func CreateSecret(document *Document, name, description string, environments []string) error {
	if err := RequireName(SecretName, name); err != nil {
		return err
	}
	if document.Secrets.Has(name) {
		return newError(CodeConflict, "Secret %s already exists", name)
	}
	document.Secrets.Set(name, &SecretEntry{})
	if err := DescribeSecret(document, name, description); err != nil {
		return err
	}
	if environments != nil {
		_, err := ScopeSecret(document, name, environments)
		return err
	}
	return nil
}

// DeleteSecret deletes a secret and its values.
func DeleteSecret(document *Document, name string) error {
	if _, err := RequireSecret(document, name); err != nil {
		return err
	}
	document.Secrets.Delete(name)
	return nil
}

// DescribeSecret sets or (with "") removes the description of a secret.
func DescribeSecret(document *Document, name, description string) error {
	secret, err := RequireSecret(document, name)
	if err != nil {
		return err
	}
	text, err := NormalizeDescription(description)
	if err != nil {
		return err
	}
	secret.Description = text
	return nil
}

// ScopeSecret limits a secret to some environments (nil: all environments; an
// empty non-nil slice is an error). Values outside the scope are removed and returned.
func ScopeSecret(document *Document, name string, environments []string) ([]string, error) {
	secret, err := RequireSecret(document, name)
	if err != nil {
		return nil, err
	}
	if environments != nil {
		if len(environments) == 0 {
			return nil, newError(CodeUsage, "A secret must apply to at least one environment")
		}
		for _, environment := range environments {
			if _, err := RequireEnvironment(document, environment); err != nil {
				return nil, err
			}
		}
		secret.Environments = slices.DeleteFunc(document.Environments.Keys(), func(environment string) bool {
			return !slices.Contains(environments, environment)
		})
	} else {
		secret.Environments = nil
	}

	applicable := SecretEnvironments(document, secret)
	removed := []string{}
	for _, environment := range secret.Values.Keys() {
		if !slices.Contains(applicable, environment) {
			secret.Values.Delete(environment)
			removed = append(removed, environment)
		}
	}
	return removed, nil
}

// RenameSecret renames a secret and re-signs its values (after verifying them).
func RenameSecret(document *Document, identities []*Identity, from, to string) error {
	secret, err := RequireSecret(document, from)
	if err != nil {
		return err
	}
	if err := RequireName(SecretName, to); err != nil {
		return err
	}
	if from == to {
		return nil
	}
	if document.Secrets.Has(to) {
		return newError(CodeConflict, "Secret %s already exists", to)
	}

	affected := slots(document, func(slot Slot) bool { return slot.Secret == from })
	if err := requireValidSignatures(document, affected); err != nil {
		return err
	}

	document.Secrets.Delete(from)
	document.Secrets.Set(to, secret)
	for _, slot := range affected {
		signer, err := SignerFor(document, identities, slot.Environment, "")
		if err != nil {
			return err
		}
		secret.Values.Set(slot.Environment, ResignValue(document, to, slot.Environment, slot.value, signer))
	}
	return nil
}

// expectedFailure reports errors that make a single value impossible to re-encrypt, as opposed to bugs.
func expectedFailure(err error) bool { return IsError(err, CodeAccessDenied, CodeSignature) }

// resealSlots re-encrypts and re-signs values around a change of recipients.
// Values are decrypted and verified against the document before the change, so
// values signed by a recipient who loses access are carried over. Values that
// cannot be decrypted, or whose signatures are invalid, are reported and left
// as is: re-encrypting them would launder tampered data.
func resealSlots(document *Document, identities []*Identity, targets []slotValue, change func()) (SyncResult, error) {
	result := SyncResult{Updated: []Slot{}, Skipped: []SkippedSlot{}}
	type opened struct {
		Slot
		plaintext []byte
	}
	var openedSlots []opened
	defer func() {
		for _, slot := range openedSlots {
			clear(slot.plaintext)
		}
	}()

	for _, target := range targets {
		plaintext, err := OpenValue(document, target.Secret, target.Environment, target.value, identities)
		if err != nil {
			if !expectedFailure(err) {
				return SyncResult{}, err
			}
			result.Skipped = append(result.Skipped, SkippedSlot{target.Slot, err.Error()})
			continue
		}
		openedSlots = append(openedSlots, opened{target.Slot, plaintext})
	}

	change()
	for _, slot := range openedSlots {
		sealed, err := resealOne(document, identities, slot.Slot, slot.plaintext)
		if err != nil {
			if !expectedFailure(err) {
				return SyncResult{}, err
			}
			result.Skipped = append(result.Skipped, SkippedSlot{slot.Slot, err.Error()})
			continue
		}
		secret, _ := document.Secrets.Get(slot.Secret)
		secret.Values.Set(slot.Environment, sealed)
		result.Updated = append(result.Updated, slot.Slot)
	}
	return result, nil
}

func resealOne(document *Document, identities []*Identity, slot Slot, plaintext []byte) (*SealedValue, error) {
	if _, err := RequireSecret(document, slot.Secret); err != nil {
		return nil, err
	}
	signer, err := SignerFor(document, identities, slot.Environment, "")
	if err != nil {
		return nil, err
	}
	return SealValue(document, slot.Secret, slot.Environment, plaintext, signer)
}

// Sync re-encrypts values whose recipient set is outdated (stale), in the
// given environments (nil: all environments).
func Sync(document *Document, identities []*Identity, environments []string) (SyncResult, error) {
	var stateErr error
	targets := slots(document, func(slot Slot) bool {
		if environments != nil && !slices.Contains(environments, slot.Environment) {
			return false
		}
		cell, err := InspectCell(document, slot.Secret, slot.Environment)
		if err != nil && stateErr == nil {
			stateErr = err
		}
		return cell.State == StateStale
	})
	if stateErr != nil {
		return SyncResult{}, stateErr
	}
	return resealSlots(document, identities, targets, func() {})
}
