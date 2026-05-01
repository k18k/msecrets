import { Command } from "commander";

import { keyImportCommand } from "./import.ts";
import { keyRemoveCommand } from "./remove.ts";

export const keyCommand = new Command()
  .command("key")
  .description("Manage configured keys")
  .addCommand(keyImportCommand)
  .addCommand(keyRemoveCommand);
