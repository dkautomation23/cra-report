#!/usr/bin/env node
/** The program. `cli.ts` holds `run`, so the tests can call it without a process. */

import { run } from "./cli.js";

// `process.exitCode` rather than `process.exit()`: ending the process while a
// keep-alive socket from `fetch` is still open makes libuv assert on Windows and
// the shell sees 127 instead of the code this tool meant to return.
run(process.argv.slice(2)).then(
  (code) => {
    process.exitCode = code;
  },
  (error: unknown) => {
    process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
    process.exitCode = 2;
  },
);
