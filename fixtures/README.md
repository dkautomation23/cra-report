# Fixtures

These files are test input, not a project.

`package-lock.json` deliberately pins **old, vulnerable versions** — that is the
whole point: the tests assert that cra-report finds the components in it that
appear in the CISA KEV catalogue. A fixture that was up to date would prove
nothing.

So: do not "fix" the versions here, and do not let a bot do it either.
Dependabot's automated security updates are switched off for this repository
for exactly this reason. Real dependencies live in the root `package.json`,
which has none at runtime.
