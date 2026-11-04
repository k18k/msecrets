package core

import (
	"errors"
	"fmt"
)

// ErrorCode classifies an [Error]. The strings match the TypeScript implementation.
type ErrorCode string

// Error codes.
const (
	// CodeAgeHeader: the age header is malformed or a recipient stanza is invalid.
	CodeAgeHeader ErrorCode = "AGE_HEADER"
	// CodeAgeNoMatch: none of the provided identities can unwrap the file key.
	CodeAgeNoMatch ErrorCode = "AGE_NO_MATCH"
	// CodeAgeHMAC: the file key was unwrapped, but the header MAC does not match.
	CodeAgeHMAC ErrorCode = "AGE_HMAC"
	// CodeAgePayload: the encrypted payload is truncated, tampered with, or malformed.
	CodeAgePayload ErrorCode = "AGE_PAYLOAD"
	// CodeAgeArmor: the ASCII armor is malformed.
	CodeAgeArmor ErrorCode = "AGE_ARMOR"
	// CodeInvalidKey: a key, identity, or recipient string is malformed.
	CodeInvalidKey ErrorCode = "INVALID_KEY"
	// CodeInvalidFile: the secrets file does not match the v4 format.
	CodeInvalidFile ErrorCode = "INVALID_FILE"
	// CodeSignature: a value signature is missing, malformed, or does not verify.
	CodeSignature ErrorCode = "SIGNATURE"
	// CodeAccessDenied: none of the loaded identities is allowed to perform the operation.
	CodeAccessDenied ErrorCode = "ACCESS_DENIED"
	// CodeNotFound: a secret, environment, recipient, or file does not exist.
	CodeNotFound ErrorCode = "NOT_FOUND"
	// CodeConflict: the operation conflicts with existing state.
	CodeConflict ErrorCode = "CONFLICT"
	// CodeIdentitySource: an identity source (env, file, keychain, password manager) failed.
	CodeIdentitySource ErrorCode = "IDENTITY_SOURCE"
	// CodeUnsupported: the runtime lacks a required capability.
	CodeUnsupported ErrorCode = "UNSUPPORTED"
	// CodeUsage: the caller passed invalid arguments.
	CodeUsage ErrorCode = "USAGE"
)

// Error is the error type of every expected failure of this package.
type Error struct {
	Code    ErrorCode
	Message string
	// Cause is the underlying error, if any.
	Cause error
}

func (e *Error) Error() string { return e.Message }

// Unwrap returns the cause.
func (e *Error) Unwrap() error { return e.Cause }

func newError(code ErrorCode, format string, args ...any) *Error {
	return &Error{Code: code, Message: fmt.Sprintf(format, args...)}
}

func wrapError(code ErrorCode, cause error, format string, args ...any) *Error {
	return &Error{Code: code, Message: fmt.Sprintf(format, args...), Cause: cause}
}

// IsError reports whether err is (or wraps) an [*Error], with one of the given codes if any are given.
func IsError(err error, codes ...ErrorCode) bool {
	var e *Error
	if !errors.As(err, &e) {
		return false
	}
	if len(codes) == 0 {
		return true
	}
	for _, code := range codes {
		if e.Code == code {
			return true
		}
	}
	return false
}
