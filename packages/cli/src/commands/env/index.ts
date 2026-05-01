import { Command } from "commander";
import { envAddCommand } from "./add.ts";
import { envListCommand } from "./list.ts";
import { envRenameCommand } from "./rename.ts";
import { envRmCommand } from "./rm.ts";

export const envCommand = new Command()
  .command("env")
  .description("Manage environments")
  .addCommand(envAddCommand)
  .addCommand(envListCommand)
  .addCommand(envRenameCommand)
  .addCommand(envRmCommand);
