#!/usr/bin/env node
import { program } from "./program.ts";
import { argv } from "node:process";

await program.parseAsync(argv);
