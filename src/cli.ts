#!/usr/bin/env node
import { buildProgram, normalizeArgv } from "./cli-program.js";
import { runServer } from "./index.js";

const program = buildProgram(async (options) => {
  await runServer(options);
});

await program.parseAsync(normalizeArgv(process.argv.slice(2)), { from: "user" });
