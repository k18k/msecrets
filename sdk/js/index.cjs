"use strict";
// @msecrets/ts-sdk: a thin synchronous wrapper around the Go core (msecrets.wasm).
const fs = require("node:fs");
const path = require("node:path");
const childProcess = require("node:child_process");
const os = require("node:os");

class MsecretsError extends Error {
  constructor(code, message, options) {
    super(message, options);
    this.name = "MsecretsError";
    this.code = code;
  }
}

function isMsecretsError(error, code) {
  return error instanceof MsecretsError && (code === undefined || error.code === code);
}

let bridge;

// Starts the Go runtime once, synchronously: main() registers its functions on the bridge and blocks.
function go() {
  if (bridge) {
    return bridge;
  }
  const helpers = {
    fs,
    os,
    childProcess,
    invoke(fn, self, ...args) {
      try {
        return { ok: true, value: Reflect.apply(fn, self, args) };
      } catch (error) {
        return { ok: false, error };
      }
    },
    sleep(ms) {
      Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);
    },
  };
  // wasm_exec.js defines the globals Go, fs, and path; this scope keeps them off the real global object.
  const own = { fs, path, __msecrets: helpers };
  const scope = new Proxy(globalThis, {
    get: (target, key) => (key in own ? own[key] : Reflect.get(target, key)),
    set: (_, key, value) => {
      own[key] = value;
      return true;
    },
  });
  const source = fs.readFileSync(path.join(__dirname, "wasm_exec.js"), "utf8");
  new Function("globalThis", "fs", source)(scope, fs);
  const runtime = new own.Go();
  const module = new WebAssembly.Module(fs.readFileSync(path.join(__dirname, "msecrets.wasm")));
  // run() executes main() synchronously up to its first block; its promise only settles on exit.
  runtime.run(new WebAssembly.Instance(module, runtime.importObject));
  if (typeof helpers.reveal !== "function") {
    throw new MsecretsError("UNSUPPORTED", "The msecrets WebAssembly module did not start");
  }
  return (bridge = helpers);
}

function call(name, ...args) {
  const result = go()[name](...args);
  if ("value" in result) {
    return result.value;
  }
  if ("thrown" in result) {
    throw result.thrown;
  }
  throw result.code ? new MsecretsError(result.code, result.message) : new Error(result.message);
}

// Identity sources are descriptors that the Go core interprets; load() is for direct use.
const DESCRIPTOR = Symbol("msecrets.source");

function source(descriptor) {
  const label = call("source", descriptor);
  return Object.freeze({ label, load: () => call("load", descriptor), [DESCRIPTOR]: descriptor });
}

const fromString = (text, label = "inline identity", options = {}) =>
  source({ ...options, kind: "string", text, label });
const fromEnv = (variable = "MSECRETS_IDENTITY", options = {}) =>
  source({ ...options, kind: "env", variable });
const fromFile = (path, options = {}) => source({ ...options, kind: "file", path });
const fromCommand = (argv, options = {}) => source({ ...options, kind: "command", argv: [...argv] });
const fromKeychain = (account = "default") => source({ kind: "keychain", account });
const parseSourceSpec = (spec, options = {}) => source({ ...options, kind: "spec", spec });
const autoSource = (options = {}) => source({ ...options, kind: "auto" });

// Strings are raw identities or source specs; like the default chain, encrypted identity files
// unlock with MSECRETS_PASSPHRASE. Custom sources ({label, load}) are loaded here.
function descriptors(entry) {
  if (typeof entry === "string") {
    const trimmed = entry.trim();
    return /^AGE-SECRET-KEY-|^-----BEGIN /i.test(trimmed)
      ? { kind: "string", text: trimmed, label: "inline identity", passphrase: "env" }
      : { kind: "spec", spec: trimmed, passphrase: "env" };
  }
  return (
    entry[DESCRIPTOR] ??
    entry.load().map((loaded) => ({
      kind: "string",
      text: loaded.identity,
      label: loaded.source ?? entry.label,
    }))
  );
}

function createClient(file, options = {}) {
  const text = JSON.stringify(file);
  const { environment, names } = call("environment", text, options.env ?? "");
  const values = names.length
    ? call("reveal", text, environment, (options.identities ?? [autoSource()]).flatMap(descriptors))
    : [];
  const secrets = Object.fromEntries(names.map((name, index) => [name, values[index]]));
  Object.defineProperty(secrets, Symbol.for("nodejs.util.inspect.custom"), {
    value: () => `Secrets (${environment}) { ${names.join(", ")} }`,
  });
  return Object.freeze(secrets);
}

function injectEnv(file, options = {}) {
  const target = options.target ?? process.env;
  const secrets = createClient(file, options);
  return Object.keys(secrets).flatMap((name) => {
    if (!options.override && target[name] !== undefined) {
      return [];
    }
    target[name] = secrets[name];
    return [name];
  });
}

module.exports = {
  MsecretsError,
  autoSource,
  createClient,
  fromCommand,
  fromEnv,
  fromFile,
  fromKeychain,
  fromString,
  injectEnv,
  isMsecretsError,
  parseSourceSpec,
};
