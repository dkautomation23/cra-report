#!/bin/bash -eu
# The fuzz target imports from dist/, so the TypeScript is compiled before the
# target is packaged.
npm ci
npm run build
compile_javascript_fuzzer cra-report fuzz/parse.fuzz.js --sync
# Five real files: a CycloneDX SBOM, a package-lock, a KEV feed, pinned
# requirements and a Cargo.lock. Starting from valid input reaches the
# interesting states sooner than random bytes do.
zip -j "$OUT/parse.fuzz_seed_corpus.zip" fuzz/seeds/*
