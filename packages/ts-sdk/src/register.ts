/**
 * Preload entry point: decrypts the selected environment into process.env
 * before the application starts. Variables that are already set win.
 *
 *   node --import @msecrets/ts-sdk/register app.js
 *   node --require @msecrets/ts-sdk/register app.js
 */
import { injectEnv } from "./index.ts";

try {
  injectEnv();
} catch (error) {
  process.stderr.write(`msecrets: ${error instanceof Error ? error.message : String(error)}\n`);
  process.exit(1);
}
