# Contributing

## Setup

    npm ci

Node.js 22 or later (see `engines` in package.json; CI runs 22.x and 24.x).

## Build

    npm run build

Runs `tsc`, compiling `src/**/*.ts` and `test/**/*.ts` (see tsconfig.json)
to `dist/`.

## Test

    npm test

Runs `npm run build` and then `node --test "dist/test/**/*.test.js"` — the
compiled tests, via Node's own test runner. There is no separate lint or
format command; `tsc --strict` is what catches type errors.

## What CI checks

`.github/workflows/ci.yml` runs on every push to `main` and on every pull
request, on a Node.js 22.x / 24.x matrix:

    npm ci
    npm run build
    node --test "dist/test/**/*.test.js"

A pull request has to pass on both Node versions.

## Adding a new check

Most changes here either teach `src/components.ts` a new SBOM/lockfile
format, or change what `assess()` (`src/assess.ts`) counts as exploited.
Add the failing case to `test/unit.test.ts` first — a component or finding
that should now appear, or should now be excluded — and only then implement
it. `fixtures/` at the repo root has sample KEV and OSV payloads to build
on.

## Commit messages

One line, sentence case, no trailing period, says what the commit does for
the tool rather than how it does it — for example, from this repo's own
history:

    Ship the code and its types, not dangling source maps
    Exit without crashing on Windows
    Test count, as the suite now runs it

## Scope

`dist/` is build output, not source — don't edit it or include it in a diff.
