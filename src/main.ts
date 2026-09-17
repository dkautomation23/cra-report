#!/usr/bin/env node
/** The program. `cli.ts` holds `run`, so the tests can call it without a process. */

import { run } from "./cli.js";

run(process.argv.slice(2)).then(
  (code) => process.exit(code),
  (error: unknown) => {
    process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
    process.exit(2);
  },
);
