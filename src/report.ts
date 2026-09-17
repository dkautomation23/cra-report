/**
 * The two things you need at 3am: the screen, and the draft.
 *
 * The draft is not a submission. Article 14 notifications go to the ENISA
 * Single Reporting Platform and nowhere else — not by email, not to a national
 * portal — and a human has to answer the questions only a human can answer.
 * What this writes is everything the form asks that a machine already knows,
 * so the person filling it in starts from facts instead of from a blank page.
 */

import { isExploited, type Finding, type Summary } from "./assess.js";
import type { Kev } from "./sources.js";

export interface Provenance {
  input: string;
  kind: string;
  kevReleased: string;
  unpinned: number;
}

const BAR = "-".repeat(72);

export function renderConsole(summary: Summary, provenance: Provenance): string {
  const lines: string[] = [];
  lines.push(BAR);
  lines.push(`CRA REPORT - ${provenance.input} (${provenance.kind})`);
  lines.push(BAR);
  lines.push(`${summary.components} component(s) read, KEV catalogue of ${provenance.kevReleased}`);
  if (provenance.unpinned > 0) {
    lines.push(
      `WARNING: ${provenance.unpinned} requirement(s) are not pinned and were skipped - an unpinned`,
    );
    lines.push("         range does not say which version is installed, and guessing would be worse.");
  }
  lines.push("");

  if (summary.exploited.length === 0) {
    lines.push("No component carries a vulnerability that is known to be exploited in the wild.");
    lines.push(`(${summary.findings} other advisory/advisories across ${summary.vulnerable} component(s) - `);
    lines.push(" ordinary maintenance, no Article 14 clock.)");
    return lines.join("\n");
  }

  lines.push(`ACTIVELY EXPLOITED: ${summary.exploited.length} finding(s) - Article 14 may apply`);
  lines.push("");
  for (const finding of summary.exploited) {
    const cves = finding.kev.map((entry) => entry.cveID).join(", ");
    lines.push(`  ${finding.component.name} ${finding.component.version}  (${finding.component.ecosystem})`);
    lines.push(`    ${finding.vulnerability.id}  ${cves}`);
    if (finding.vulnerability.summary) lines.push(`    ${finding.vulnerability.summary.split("\n")[0]}`);
    for (const entry of finding.kev) {
      const ransom = entry.knownRansomwareCampaignUse === "Known" ? "  [used in ransomware campaigns]" : "";
      lines.push(`    in CISA KEV since ${entry.dateAdded}${ransom}`);
    }
    if (finding.vulnerability.fixedIn.length > 0) {
      lines.push(`    fixed in ${finding.vulnerability.fixedIn.join(", ")}`);
    }
    lines.push("");
  }

  if (summary.ransomware > 0) {
    lines.push(`${summary.ransomware} of these are known to be used in ransomware campaigns.`);
  }
  lines.push(
    `${summary.findings - summary.exploited.length} further advisory/advisories are known but not ` +
      "observed being exploited.",
  );
  lines.push("");
  lines.push("Article 14(1): early warning within 24 hours of becoming aware, fuller notification");
  lines.push("within 72 hours, via the ENISA Single Reporting Platform. Write the draft with --draft.");
  return lines.join("\n");
}

/** The early-warning draft: what a machine can fill in, and explicit gaps where it cannot. */
export function renderDraft(findings: Finding[], provenance: Provenance, now = new Date()): string {
  const exploited = findings.filter(isExploited);
  const deadline = new Date(now.getTime() + 24 * 3600 * 1000);

  const lines: string[] = [];
  lines.push("# CRA Article 14(1) early warning - DRAFT");
  lines.push("");
  lines.push("> Not a submission. Article 14 notifications are filed through the");
  lines.push("> ENISA Single Reporting Platform and no other channel — not by email, not to a");
  lines.push("> national portal. Fields marked **TO COMPLETE** need a person; everything else");
  lines.push("> is filled in from the evidence below.");
  lines.push("");
  lines.push(`- **Became aware (UTC):** ${now.toISOString()}`);
  lines.push("  *Confirm this: the clock starts when your organisation became aware, which may be*");
  lines.push("  *earlier than this scan.*");
  lines.push(`- **24-hour early warning due:** ${deadline.toISOString()}`);
  lines.push("- **Manufacturer:** TO COMPLETE");
  lines.push("- **Product and version placed on the EU market:** TO COMPLETE");
  lines.push("- **Contact point:** TO COMPLETE");
  lines.push(`- **Evidence:** \`${provenance.input}\` (${provenance.kind}), CISA KEV catalogue of ${provenance.kevReleased}`);
  lines.push("");

  lines.push("## Vulnerabilities observed being exploited");
  lines.push("");
  if (exploited.length === 0) {
    lines.push("None found in the components read. No Article 14 notification is triggered by this scan.");
    return lines.join("\n");
  }

  for (const finding of exploited) {
    const cves = finding.kev.map((entry) => entry.cveID);
    lines.push(`### ${cves.join(", ")} — ${finding.component.name} ${finding.component.version}`);
    lines.push("");
    lines.push(`- **Component:** \`${finding.component.name}@${finding.component.version}\` (${finding.component.ecosystem})`);
    lines.push(`- **Advisory:** ${finding.vulnerability.id}${finding.vulnerability.severity ? ` (${finding.vulnerability.severity})` : ""}`);
    if (finding.vulnerability.summary) lines.push(`- **Summary:** ${finding.vulnerability.summary.split("\n")[0]}`);
    for (const entry of finding.kev) {
      lines.push(`- **Exploitation:** in CISA KEV since ${entry.dateAdded}${entry.knownRansomwareCampaignUse === "Known" ? ", used in ransomware campaigns" : ""}`);
      if (entry.shortDescription) lines.push(`- **CISA description:** ${entry.shortDescription}`);
      if (entry.requiredAction) lines.push(`- **CISA required action:** ${entry.requiredAction}`);
    }
    lines.push(
      finding.vulnerability.fixedIn.length > 0
        ? `- **Fixed upstream in:** ${finding.vulnerability.fixedIn.join(", ")}`
        : "- **Fixed upstream in:** no fixed version published at the time of this scan",
    );
    lines.push("- **Is the affected code reachable in your product?** TO COMPLETE");
    lines.push("- **Corrective or mitigating measures taken:** TO COMPLETE");
    lines.push("- **Users affected / notified:** TO COMPLETE");
    lines.push("");
  }

  lines.push("## Timeline");
  lines.push("");
  lines.push("| Obligation | Due |");
  lines.push("| --- | --- |");
  lines.push(`| Early warning (Art. 14(1)) | ${deadline.toISOString()} |`);
  lines.push(`| Vulnerability notification (Art. 14(2)) | ${new Date(now.getTime() + 72 * 3600 * 1000).toISOString()} |`);
  lines.push("| Final report (Art. 14(4)) | within 14 days of a corrective measure being available |");
  return lines.join("\n");
}

export function renderJson(findings: Finding[], summary: Summary, provenance: Provenance, kev: Kev): string {
  return `${JSON.stringify(
    {
      generatedAt: new Date().toISOString(),
      input: provenance.input,
      inputKind: provenance.kind,
      kevReleased: kev.released,
      kevEntries: kev.count,
      componentsRead: summary.components,
      reportable: summary.exploited.length,
      findings: findings.map((finding) => ({
        component: finding.component,
        advisory: finding.vulnerability.id,
        cves: finding.kev.map((entry) => entry.cveID),
        activelyExploited: isExploited(finding),
        ransomware: finding.kev.some((entry) => entry.knownRansomwareCampaignUse === "Known"),
        fixedIn: finding.vulnerability.fixedIn,
        summary: finding.vulnerability.summary,
      })),
    },
    null,
    2,
  )}\n`;
}
