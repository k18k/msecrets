// Package core is the msecrets v4 library: the msecrets.json file format,
// keys and identities, sealing and verification of values, inspection,
// mutations, file storage, and identity sources. The CLI, the terminal UI, and
// the WebAssembly SDK only call it and render its results.
//
// # Model
//
// A [Document] holds recipients (named public keys), environments (ordered;
// each lists the recipients that can read it), and secrets (one
// [SealedValue] per environment). Every value is an age file encrypted to the
// recipients of its environment and signed (Ed25519) by one of them.
//
// # Typical use
//
//	h := core.NativeHost()                               // or a custom Host (js/wasm)
//	path, err := core.ResolveDocumentFile(h, "", "")     // --file, MSECRETS_FILE, or upward search
//	loaded, err := core.LoadIdentities([]core.IdentitySource{core.AutoSource(core.SourceOptions{Host: h})})
//	identities := ...                                    // loaded[i].Identity
//	document, err := core.ReadDocumentFile(h, path)
//	value, err := core.RevealValue(document, identities, "DATABASE_URL", "production")
//
//	// Mutations run inside UpdateDocumentFile: locked, validated, atomic, conflict-checked.
//	_, err = core.UpdateDocumentFile(h, path, func(d *core.Document) (*core.SealedValue, error) {
//		return core.SetValue(d, identities, core.SetValueInput{Secret: "API_KEY", Environment: "production", Value: v})
//	})
//
// Status needs public data only: [Inspect] and [InspectCell] report missing,
// stale, invalid, and unexpected values, and access warnings.
//
// # Host
//
// All access to the environment, files, and processes goes through [Host].
// [NativeHost] uses the os and os/exec packages; under js/wasm the SDK provides
// a Host backed by Node.js synchronous APIs. [WithEnv] substitutes an
// environment map (for example a copy that identity sources scrub).
//
// # Errors
//
// Failures are [*Error] values with an [ErrorCode] (the same codes and messages
// as the TypeScript implementation); test them with [IsError]. Expected
// outcomes are return values: "not found" is "" or false, a failed signature
// check is a non-empty [SignatureProblem] or [StateInvalid].
//
// # Compatibility
//
// Files written by [SerializeDocument] are byte-identical to the TypeScript
// implementation, including key order (see [Map]). Parsing is strict: valid
// UTF-8 only, no duplicate keys or lone surrogates, at most 64 MiB.
//
// # Security invariants
//
//   - Values are decrypted, re-encrypted, or re-signed only after their signature verifies.
//   - Revocation re-encrypts every affected value or fails (unless allowIncomplete).
//   - Writers must be recipients of the environment with a signing key; age1… keys are read-only.
//   - Identity variables are scrubbed from the environment after reading (unless NoScrub).
//   - Untrusted text in messages is sanitized of control characters.
package core
