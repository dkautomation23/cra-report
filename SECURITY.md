# Security Policy

## Reporting a vulnerability

Please do not open a public issue for a security problem.

- GitHub: use "Report a vulnerability" under this repository's Security tab
  (Private vulnerability reporting) —
  https://github.com/dkautomation23/cra-report/security/advisories/new
- Email: hello@dkautomation.dev

Include what you ran, what you expected, what happened instead, and the
smallest input file that reproduces it (strip anything private from it
first).

We aim to send a first response within 3 business days.

## Supported versions

| Version | Supported |
| --- | --- |
| 0.1.x (latest release) | yes |
| anything older | no |

cra-report has not reached 1.0. Only the latest published release is
supported — update before reporting.

## Scope

cra-report reads a component list from an SBOM or lock file you give it,
checks each component against osv.dev, and cross-references the result
against the CISA KEV catalogue to decide whether a component is *actively
exploited* — the fact that starts the Article 14 clock. The determination
of "exploited or not" is the part worth protecting.

In scope:

- A crafted SBOM or lock file (CycloneDX, SPDX, `package-lock.json`,
  `Cargo.lock`, pinned `requirements.txt`) that makes cra-report silently
  drop or misidentify a component, so that something actually listed in
  CISA KEV is not reported as exploited — for example, a parsing bug in
  `src/components.ts` that misreads a name, version, or ecosystem, or a
  matching bug in `cveIdsOf()` (`src/sources.ts`) that fails to connect an
  OSV advisory to its KEV entry.
- The reverse: an input that makes `assess()` (`src/assess.ts`) report a
  component as actively exploited when it is not in the CISA KEV catalogue.
- A `--kev` file that isn't validated and crashes the tool instead of
  failing with a clear error — this is meant to run unattended in CI or
  cron, and a crash there is a missed detection.

Out of scope:

- Whether a flagged component legally obliges *you* to file an Article 14
  notification for your product. The code and the generated draft are
  explicit that this needs a human (see the `TO COMPLETE` fields in
  `renderDraft`); that judgment call is not a vulnerability in the tool.
- osv.dev or the CISA KEV feed themselves being wrong, slow, or
  unreachable — third-party data sources this tool reads, not part of it.
- `--draft` / `--json` writing to whatever local path you name, or `--kev`
  reading whatever local path you name — your own command line.
