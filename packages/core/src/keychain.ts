/**
 * OS credential stores without native dependencies: macOS Keychain (`security`),
 * the Linux Secret Service (`secret-tool`), and the Windows Credential Manager
 * (PowerShell + advapi32). Secrets never appear on command lines.
 */
import { spawnSync } from "node:child_process";

import { MsecretsError } from "./errors.ts";

const SERVICE = "msecrets";
const TIMEOUT = 60_000;

const WINDOWS_CREDENTIALS = String.raw`
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
`;

const NOT_FOUND_EXIT = 44;

/** `security` exits with errSecItemNotFound (44); our PowerShell script uses the same code. */
const exitedNotFound = (status: number | null): boolean => status === NOT_FOUND_EXIT;
/** `secret-tool lookup` exits with 1 and prints nothing when there is no match. */
const secretToolNotFound = (status: number | null, stderr: string): boolean =>
  status === 1 && !stderr.trim();
const neverNotFound = (): boolean => false;

type Command = {
  command: string;
  args: string[];
  input?: string;
  env?: NodeJS.ProcessEnv;
  notFound: (status: number | null, stderr: string) => boolean;
};

export type KeychainPlatform = "darwin" | "linux" | "win32";

function keychainCommand(
  platform: NodeJS.Platform,
  action: "read" | "write" | "delete",
  account: string,
  secret = "",
): Command {
  if (platform === "darwin") {
    if (action === "read") {
      return {
        command: "security",
        args: ["find-generic-password", "-s", SERVICE, "-a", account, "-w"],
        notFound: exitedNotFound,
      };
    }
    if (action === "delete") {
      return {
        command: "security",
        args: ["delete-generic-password", "-s", SERVICE, "-a", account],
        notFound: exitedNotFound,
      };
    }
    // `security -i` reads commands from stdin, keeping the secret off the process list.
    return {
      command: "security",
      args: ["-i"],
      input: `add-generic-password -U -s ${SERVICE} -a ${account} -l ${SERVICE}:${account} -w ${secret}\n`,
      notFound: neverNotFound,
    };
  }

  if (platform === "linux") {
    const attributes = ["service", SERVICE, "account", account];
    if (action === "read") {
      return {
        command: "secret-tool",
        args: ["lookup", ...attributes],
        notFound: secretToolNotFound,
      };
    }
    if (action === "delete") {
      return { command: "secret-tool", args: ["clear", ...attributes], notFound: neverNotFound };
    }
    return {
      command: "secret-tool",
      args: ["store", `--label=msecrets (${account})`, ...attributes],
      input: secret,
      notFound: neverNotFound,
    };
  }

  if (platform === "win32") {
    return {
      command: "powershell.exe",
      args: [
        "-NoProfile",
        "-NonInteractive",
        "-ExecutionPolicy",
        "Bypass",
        "-EncodedCommand",
        Buffer.from(WINDOWS_CREDENTIALS, "utf16le").toString("base64"),
      ],
      input: secret,
      env: {
        ...process.env,
        MSECRETS_KEYCHAIN_ACTION: action,
        MSECRETS_KEYCHAIN_TARGET: `${SERVICE}:${account}`,
        MSECRETS_KEYCHAIN_ACCOUNT: account,
      },
      notFound: exitedNotFound,
    };
  }

  throw new MsecretsError("UNSUPPORTED", `No OS keychain integration for platform ${platform}`);
}

function run(
  platform: NodeJS.Platform,
  action: "read" | "write" | "delete",
  account: string,
  secret?: string,
): string | null {
  if (!/^[a-z0-9][a-z0-9._@+-]{0,62}$/.test(account)) {
    throw new MsecretsError("USAGE", `Invalid keychain account name "${account}"`);
  }

  const command = keychainCommand(platform, action, account, secret);
  const result = spawnSync(command.command, command.args, {
    encoding: "utf8",
    input: command.input ?? "",
    env: command.env ?? process.env,
    timeout: TIMEOUT,
    windowsHide: true,
    maxBuffer: 1024 * 1024,
  });

  if (result.error) {
    const missing = (result.error as NodeJS.ErrnoException).code === "ENOENT";
    throw new MsecretsError(
      "IDENTITY_SOURCE",
      missing
        ? `The OS keychain tool \`${command.command}\` is not installed${platform === "linux" ? " (install libsecret-tools / libsecret)" : ""}`
        : `Failed to run \`${command.command}\`: ${result.error.message}`,
      { cause: result.error },
    );
  }
  if (result.status === 0) {
    return result.stdout;
  }
  if (command.notFound(result.status, result.stderr)) {
    return null;
  }
  throw new MsecretsError(
    "IDENTITY_SOURCE",
    `OS keychain ${action} failed (${command.command} exited with ${result.status ?? result.signal}): ${result.stderr.trim() || "no details"}`,
  );
}

/** Reads the msecrets identity stored under an account, or null if there is none. */
export function readKeychain(
  account: string,
  platform: NodeJS.Platform = process.platform,
): string | null {
  const value = run(platform, "read", account);
  return value === null ? null : value.replace(/\r?\n$/, "");
}

export function writeKeychain(
  account: string,
  secret: string,
  platform: NodeJS.Platform = process.platform,
): void {
  if (!/^[\x21-\x7e]+$/.test(secret)) {
    throw new MsecretsError(
      "USAGE",
      "Only single-line identities (AGE-SECRET-KEY-…) can be stored in the OS keychain",
    );
  }
  run(platform, "write", account, secret);
  // Some tools report success even when the write failed, so read it back.
  if (readKeychain(account, platform) !== secret) {
    throw new MsecretsError(
      "IDENTITY_SOURCE",
      `The OS keychain did not store the identity for "${account}"`,
    );
  }
}

export function deleteKeychain(
  account: string,
  platform: NodeJS.Platform = process.platform,
): boolean {
  return run(platform, "delete", account) !== null;
}
