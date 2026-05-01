import { Command } from "commander";

import { secretCreateCommand } from "./create.ts";
import { secretDeleteCommand } from "./delete.ts";
import { secretPeekCommand } from "./peek.ts";
import { secretRenameCommand } from "./rename.ts";
import { secretRevokeCommand } from "./revoke.ts";
import { secretRmCommand } from "./rm.ts";
import { secretShareCommand } from "./share.ts";
import { secretSetCommand } from "./set.ts";

export const secretCommand = new Command()
  .command("secret")
  .description("Manage secrets")
  .addCommand(secretCreateCommand)
  .addCommand(secretDeleteCommand)
  .addCommand(secretSetCommand)
  .addCommand(secretRenameCommand)
  .addCommand(secretShareCommand)
  .addCommand(secretRevokeCommand)
  .addCommand(secretPeekCommand)
  .addCommand(secretRmCommand);
