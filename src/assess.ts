/**
 * Deciding which findings start a 24-hour clock, and which do not.
 *
 * CRA Article 14(1) obliges a manufacturer to notify an *actively exploited*
 * vulnerability in its product: an early warning within 24 hours of becoming
 * aware of it, a fuller notification within 72 hours. Everything else on a
 * scanner's screen is ordinary maintenance work with no statutory clock.
 *
 * Nothing here decides whether *you* must report. That depends on whether the
 * component is reachable in your product and whether you are the manufacturer
 * placing it on the EU market — questions no tool can answer from a lock file.
 * What it does is narrow a hundred advisories to the two that are worth waking
 * someone up about, and hand over the facts in the shape the form asks for.
 */

import type { Component } from "./components.js";
import { cveIdsOf, type Kev, type KevEntry, type Vulnerability } from "./sources.js";

export interface Finding {
  component: Component;
  vulnerability: Vulnerability;
  /** KEV entries matching this vulnerability's CVE ids. Non-empty = exploited. */
  kev: KevEntry[];
}

export function isExploited(finding: Finding): boolean {
  return finding.kev.length > 0;
}

export function assess(
  components: Component[],
  vulnIdsPerComponent: string[][],
  vulnerabilities: Map<string, Vulnerability>,
  kev: Kev,
): Finding[] {
  const findings: Finding[] = [];

  for (const [index, component] of components.entries()) {
    for (const id of vulnIdsPerComponent[index] ?? []) {
      const vulnerability = vulnerabilities.get(id);
      if (!vulnerability) continue;

      const matches: KevEntry[] = [];
      for (const cve of cveIdsOf(vulnerability)) {
        const entry = kev.byCve.get(cve);
        if (entry) matches.push(entry);
      }
      findings.push({ component, vulnerability, kev: matches });
    }
  }

  // Exploited first, then by component, so the top of the output is the part
  // with a deadline attached.
  return findings.sort((a, b) => {
    const exploited = Number(isExploited(b)) - Number(isExploited(a));
    if (exploited !== 0) return exploited;
    return a.component.name.localeCompare(b.component.name);
  });
}

export interface Summary {
  components: number;
  vulnerable: number;
  findings: number;
  exploited: Finding[];
  ransomware: number;
}

export function summarise(components: Component[], findings: Finding[]): Summary {
  const exploited = findings.filter(isExploited);
  return {
    components: components.length,
    vulnerable: new Set(findings.map((finding) => `${finding.component.name}@${finding.component.version}`)).size,
    findings: findings.length,
    exploited,
    ransomware: exploited.filter((finding) =>
      finding.kev.some((entry) => entry.knownRansomwareCampaignUse === "Known"),
    ).length,
  };
}
