package core

// OS credential stores without native dependencies: macOS Keychain (security),
// the Linux Secret Service (secret-tool), and the Windows Credential Manager
// (PowerShell + advapi32). Secrets never appear on command lines.

import (
	"encoding/base64"
	"errors"
	"fmt"
	"io/fs"
	"regexp"
	"strings"
	"time"
	"unicode/utf16"
)

const (
	keychainService = "msecrets"
	keychainTimeout = 60 * time.Second
	notFoundExit    = 44
)

const windowsCredentials = `
$ErrorActionPreference = 'Stop'
Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;
public static class MsecretsCredentials {
  [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
  private struct CREDENTIAL {
    public int Flags; public int Type; public string TargetName; public string Comment;
    public System.Runtime.InteropServices.ComTypes.FILETIME LastWritten;
    public int CredentialBlobSize; public IntPtr CredentialBlob; public int Persist;
    public int AttributeCount; public IntPtr Attributes; public string TargetAlias; public string UserName;
  }
  [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
  private static extern bool CredReadW(string target, int type, int flags, out IntPtr credential);
  [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
  private static extern bool CredWriteW(ref CREDENTIAL credential, int flags);
  [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
  private static extern bool CredDeleteW(string target, int type, int flags);
  [DllImport("advapi32.dll")]
  private static extern void CredFree(IntPtr credential);
  public static string Read(string target) {
    IntPtr pointer;
    if (!CredReadW(target, 1, 0, out pointer)) {
      int error = Marshal.GetLastWin32Error();
      if (error == 1168) { return null; }
      throw new Win32Exception(error);
    }
    try {
      CREDENTIAL credential = (CREDENTIAL)Marshal.PtrToStructure(pointer, typeof(CREDENTIAL));
      return Marshal.PtrToStringUni(credential.CredentialBlob, credential.CredentialBlobSize / 2);
    } finally { CredFree(pointer); }
  }
  public static void Write(string target, string user, string secret) {
    byte[] bytes = Encoding.Unicode.GetBytes(secret);
    CREDENTIAL credential = new CREDENTIAL();
    credential.Type = 1; credential.TargetName = target; credential.UserName = user; credential.Persist = 2;
    credential.CredentialBlobSize = bytes.Length; credential.CredentialBlob = Marshal.AllocHGlobal(bytes.Length);
    try {
      Marshal.Copy(bytes, 0, credential.CredentialBlob, bytes.Length);
      if (!CredWriteW(ref credential, 0)) { throw new Win32Exception(Marshal.GetLastWin32Error()); }
    } finally { Marshal.FreeHGlobal(credential.CredentialBlob); }
  }
  public static bool Delete(string target) {
    if (CredDeleteW(target, 1, 0)) { return true; }
    int error = Marshal.GetLastWin32Error();
    if (error == 1168) { return false; }
    throw new Win32Exception(error);
  }
}
'@
$target = $env:MSECRETS_KEYCHAIN_TARGET
switch ($env:MSECRETS_KEYCHAIN_ACTION) {
  'read' { $value = [MsecretsCredentials]::Read($target); if ($null -eq $value) { exit 44 }; [Console]::Out.Write($value) }
  'write' { [MsecretsCredentials]::Write($target, $env:MSECRETS_KEYCHAIN_ACCOUNT, [Console]::In.ReadToEnd()) }
  'delete' { if (-not [MsecretsCredentials]::Delete($target)) { exit 44 } }
}
`

type keychainCommand struct {
	Command
	notFound func(result CommandResult) bool
}

// exitedNotFound: security exits with errSecItemNotFound (44); our PowerShell script uses the same code.
func exitedNotFound(result CommandResult) bool { return result.ExitCode == notFoundExit }

// secretToolNotFound: secret-tool lookup exits with 1 and prints nothing when there is no match.
func secretToolNotFound(result CommandResult) bool {
	return result.ExitCode == 1 && strings.TrimSpace(string(result.Stderr)) == ""
}

func neverNotFound(CommandResult) bool { return false }

func encodePowerShell(script string) string {
	units := utf16.Encode([]rune(script))
	encoded := make([]byte, 0, len(units)*2)
	for _, unit := range units {
		encoded = append(encoded, byte(unit), byte(unit>>8))
	}
	return base64.StdEncoding.EncodeToString(encoded)
}

func newKeychainCommand(h Host, action, account, secret string) (keychainCommand, error) {
	switch h.Platform() {
	case "darwin":
		switch action {
		case "read":
			return keychainCommand{Command{Path: "security", Args: []string{"find-generic-password", "-s", keychainService, "-a", account, "-w"}}, exitedNotFound}, nil
		case "delete":
			return keychainCommand{Command{Path: "security", Args: []string{"delete-generic-password", "-s", keychainService, "-a", account}}, exitedNotFound}, nil
		}
		// security -i reads commands from stdin, keeping the secret off the process list.
		input := fmt.Sprintf("add-generic-password -U -s %s -a %s -l %s:%s -w %s\n", keychainService, account, keychainService, account, secret)
		return keychainCommand{Command{Path: "security", Args: []string{"-i"}, Stdin: []byte(input)}, neverNotFound}, nil
	case "linux":
		attributes := []string{"service", keychainService, "account", account}
		switch action {
		case "read":
			return keychainCommand{Command{Path: "secret-tool", Args: append([]string{"lookup"}, attributes...)}, secretToolNotFound}, nil
		case "delete":
			return keychainCommand{Command{Path: "secret-tool", Args: append([]string{"clear"}, attributes...)}, neverNotFound}, nil
		}
		args := append([]string{"store", "--label=msecrets (" + account + ")"}, attributes...)
		return keychainCommand{Command{Path: "secret-tool", Args: args, Stdin: []byte(secret)}, neverNotFound}, nil
	case "windows":
		env := append(h.Environ(),
			"MSECRETS_KEYCHAIN_ACTION="+action,
			"MSECRETS_KEYCHAIN_TARGET="+keychainService+":"+account,
			"MSECRETS_KEYCHAIN_ACCOUNT="+account)
		return keychainCommand{Command{
			Path:  "powershell.exe",
			Args:  []string{"-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-EncodedCommand", encodePowerShell(windowsCredentials)},
			Env:   env,
			Stdin: []byte(secret),
		}, exitedNotFound}, nil
	}
	return keychainCommand{}, newError(CodeUnsupported, "No OS keychain integration for platform %s", h.Platform())
}

var keychainAccount = regexp.MustCompile(`^[a-z0-9][a-z0-9._@+-]{0,62}$`)

// runKeychain runs a keychain action; found is false when the item does not exist.
func runKeychain(h Host, action, account, secret string) (output string, found bool, err error) {
	if !keychainAccount.MatchString(account) {
		return "", false, newError(CodeUsage, "Invalid keychain account name \"%s\"", sanitize(account))
	}
	command, err := newKeychainCommand(h, action, account, secret)
	if err != nil {
		return "", false, err
	}
	if command.Env == nil {
		command.Env = h.Environ()
	}
	command.Timeout = keychainTimeout
	command.MaxOutput = commandMaxOutput

	result, err := h.Run(command.Command)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			hint := ""
			if h.Platform() == "linux" {
				hint = " (install libsecret-tools / libsecret)"
			}
			return "", false, wrapError(CodeIdentitySource, err, "The OS keychain tool `%s` is not installed%s", command.Path, hint)
		}
		return "", false, wrapError(CodeIdentitySource, err, "Failed to run `%s`: %v", command.Path, err)
	}
	if result.ExitCode == 0 {
		return string(result.Stdout), true, nil
	}
	if command.notFound(result) {
		return "", false, nil
	}
	status := fmt.Sprint(result.ExitCode)
	if result.Signal != "" {
		status = result.Signal
	}
	details := strings.TrimSpace(sanitize(string(result.Stderr)))
	if details == "" {
		details = "no details"
	}
	return "", false, newError(CodeIdentitySource, "OS keychain %s failed (%s exited with %s): %s", action, command.Path, status, details)
}

// ReadKeychain reads the msecrets identity stored under an account; found is false if there is none.
func ReadKeychain(h Host, account string) (secret string, found bool, err error) {
	output, found, err := runKeychain(h, "read", account, "")
	output = strings.TrimSuffix(strings.TrimSuffix(output, "\n"), "\r")
	return output, found, err
}

var singleLineSecret = regexp.MustCompile(`^[\x21-\x7e]+$`)

// WriteKeychain stores an identity (a single-line AGE-SECRET-KEY-…) under an account.
func WriteKeychain(h Host, account, secret string) error {
	if !singleLineSecret.MatchString(secret) {
		return newError(CodeUsage, "Only single-line identities (AGE-SECRET-KEY-…) can be stored in the OS keychain")
	}
	if _, _, err := runKeychain(h, "write", account, secret); err != nil {
		return err
	}
	// Some tools report success even when the write failed, so read it back.
	stored, _, err := ReadKeychain(h, account)
	if err != nil {
		return err
	}
	if stored != secret {
		return newError(CodeIdentitySource, "The OS keychain did not store the identity for \"%s\"", account)
	}
	return nil
}

// DeleteKeychain deletes the identity stored under an account and reports whether there was one.
func DeleteKeychain(h Host, account string) (bool, error) {
	_, found, err := runKeychain(h, "delete", account, "")
	return found, err
}
