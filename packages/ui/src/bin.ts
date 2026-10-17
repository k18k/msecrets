#!/usr/bin/env node
import { main } from "./cli.ts";
import { processIo } from "./terminal.ts";

const code = await main(process.argv.slice(2), processIo());
// Flush pending output (pipes are asynchronous), then exit even if a child left handles open.
process.stdout.write("", () => process.stderr.write("", () => process.exit(code)));
