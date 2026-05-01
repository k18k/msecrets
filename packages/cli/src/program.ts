import { envCommand } from "#commands/env/index.ts";
import { runImportKeyCommand } from "#commands/import-key.ts";
import { runInitCommand } from "#commands/init.ts";
import { keyCommand } from "#commands/key/index.ts";
import { secretCommand } from "#commands/secret/index.ts";
import { uiCommand } from "#commands/ui.ts";
import { Command } from "commander";

export const program = new Command();

program
  .name("msecrets")
  .description("Repository-native encrypted secrets CLI")
  .showHelpAfterError();

program.command("init").description("Initialize a new .env.ms.json file").action(runInitCommand);

program
  .command("import-key")
  .description("Import a public key from the local GPG keyring")
  .action(runImportKeyCommand);

program.addCommand(envCommand);
program.addCommand(keyCommand);
program.addCommand(secretCommand);
program.addCommand(uiCommand);

program.option(
  "-c, --config <path>",
  "Path to .env.ms.json",
  (r) => (r.endsWith(".json") ? r : `.env.${r}.json`),
  ".env.ms.json",
);

export const getConfigPath = () => program.opts()["config"] as string;
