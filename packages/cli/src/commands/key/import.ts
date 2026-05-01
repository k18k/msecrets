import { runImportKeyCommand } from "#commands/import-key.ts";
import { Command } from "commander";

export const keyImportCommand = new Command()
  .command("import")
  .description("Import a public key from the local GPG keyring")
  .action(runImportKeyCommand);
