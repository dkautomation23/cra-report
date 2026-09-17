/**
 * cra-report - which of your components is being exploited right now, and the
 * Article 14 draft that goes with it.
 */

import { readFileSync, writeFileSync } from "node:fs";

import { load } from "./components.js";
import { assess, summarise } from "./assess.js";
import { renderConsole, renderDraft, renderJson, type Provenance } from "./report.js";
import {
  fetchVulnerabilities,
  httpFetcher,
  kevFromJson,
  loadKev,
  queryOsv,
  type Fetcher,
  type Kev,
} from "./sources.js";

const USAGE = `cra-report - find the components you ship that are being exploited in the wild,
and draft the EU Cyber Resilience Act Article 14 notification for them.

  cra-report package-lock.json
  cra-report sbom.cdx.json --draft early-warning.md
  npx cra-report Cargo.lock --json findings.json

Input: a CycloneDX or SPDX SBOM (JSON), package-lock.json, Cargo.lock, or a
pinned requirements.txt.

  --draft FILE     write the Article 14(1) early-warning draft
  --json FILE      write every finding as JSON
  --kev FILE       use a saved CISA KEV feed instead of fetching it
  --all            list advisories that are not being exploited too
  --timeout MS     per request, default 30000
  --quiet          only write files, print nothing

Exit codes: 0 nothing exploited, 1 something exploited (Article 14 may apply),
2 the tool could not do its job. So it belongs in CI and in cron.

Data: osv.dev for advisories, CISA KEV for what is actually being exploited.
Both free, neither needs a key. This tool decides nothing for you - see the
README on what it deliberately does not claim.
`;

function parse(argv: string[]): { input?: string; flags: Map<string, string>; bools: Set<string> } {
  const flags = new Map<string, string>();
  const bools = new Set<string>();
  let input: string | undefined;

  for (let i = 0; i < argv.length; i += 1) {
    const token = argv[i]!;
    if (!token.startsWith("--")) {
      input ??= token;
      continue;
    }
    const name = token.slice(2);
    const next = argv[i + 1];
    if (next === undefined || next.startsWith("--")) bools.add(name);
    else {
      flags.set(name, next);
      i += 1;
    }
  }
  return { input, flags, bools };
}

export async function run(argv: string[], fetcher?: Fetcher, out: (text: string) => void = (t) => process.stdout.write(t)): Promise<number> {
  const args = parse(argv);
  if (!args.input || args.bools.has("help")) {
    out(USAGE);
    return args.input ? 0 : 2;
  }

  const timeout = Number(args.flags.get("timeout") ?? 30_000);
  const http = fetcher ?? httpFetcher(timeout);
  const quiet = args.bools.has("quiet");

  const loaded = load(args.input);
  if (loaded.components.length === 0) {
    out(`${args.input}: no components found\n`);
    return 2;
  }

  const kevPath = args.flags.get("kev");
  const kev: Kev = kevPath
    ? kevFromJson(JSON.parse(readFileSync(kevPath, "utf8")))
    : await loadKev(http);

  const vulnIds = await queryOsv(http, loaded.components);
  const unique = [...new Set(vulnIds.flat())];
  const vulnerabilities = await fetchVulnerabilities(http, unique);

  const findings = assess(loaded.components, vulnIds, vulnerabilities, kev);
  const summary = summarise(loaded.components, findings);

  const provenance: Provenance = {
    input: args.input,
    kind: loaded.kind,
    kevReleased: kev.released,
    unpinned: loaded.unpinned,
  };

  if (!quiet) {
    out(`${renderConsole(summary, provenance)}\n`);
    if (args.bools.has("all") && summary.findings > summary.exploited.length) {
      out("\nNot observed being exploited:\n");
      for (const finding of findings.filter((f) => f.kev.length === 0)) {
        out(`  ${finding.component.name} ${finding.component.version}  ${finding.vulnerability.id}\n`);
      }
    }
  }

  const draftPath = args.flags.get("draft");
  if (draftPath) {
    writeFileSync(draftPath, `${renderDraft(findings, provenance)}\n`, "utf8");
    if (!quiet) out(`\ndraft written to ${draftPath}\n`);
  }

  const jsonPath = args.flags.get("json");
  if (jsonPath) {
    writeFileSync(jsonPath, renderJson(findings, summary, provenance, kev), "utf8");
    if (!quiet) out(`findings written to ${jsonPath}\n`);
  }

  return summary.exploited.length > 0 ? 1 : 0;
}
