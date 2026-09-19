/**
 * The two free feeds this tool joins.
 *
 * **OSV** (osv.dev, run by the OpenSSF) answers "does this exact version have a
 * known vulnerability" for every ecosystem that matters. No key, no quota worth
 * worrying about.
 *
 * **CISA KEV** is the list of vulnerabilities *observed being exploited in the
 * wild*. That distinction is the whole tool: CRA Article 14 obliges you to
 * report an actively exploited vulnerability within 24 hours, and says nothing
 * about the hundred advisories that are not. A scanner that shouts about all of
 * them tells you nothing about which clock is running.
 */

import type { Component } from "./components.js";

export const OSV_BATCH = "https://api.osv.dev/v1/querybatch";
export const OSV_VULN = "https://api.osv.dev/v1/vulns/";
export const KEV_FEED = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";

export interface KevEntry {
  cveID: string;
  vendorProject: string;
  product: string;
  vulnerabilityName: string;
  dateAdded: string;
  dueDate?: string;
  requiredAction?: string;
  knownRansomwareCampaignUse?: string;
  shortDescription?: string;
}

export interface Kev {
  released: string;
  count: number;
  byCve: Map<string, KevEntry>;
}

export interface Fetcher {
  json(url: string, body?: unknown): Promise<unknown>;
}

/**
 * The KEV feed is a couple of megabytes and an OSV answer is smaller. A cap
 * turns "the endpoint answered with something enormous" into an error instead
 * of the machine's memory, and it is the endpoint's own choice how much it
 * sends - not ours.
 */
export const MAX_FEED_BYTES = 64 * 1024 * 1024;

async function readCapped(response: Response, limit: number, url: string): Promise<string> {
  if (!response.body) return "";
  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  let text = "";
  let bytes = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      bytes += value.byteLength;
      if (bytes > limit) {
        await reader.cancel();
        throw new Error(`${url} returned more than ${limit} bytes; that is not a vulnerability feed`);
      }
      text += decoder.decode(value, { stream: true });
    }
  } finally {
    reader.releaseLock();
  }
  return text + decoder.decode();
}

/** The real one. Tests pass their own, so nothing in the suite touches a network. */
export function httpFetcher(timeoutMs: number): Fetcher {
  return {
    async json(url, body) {
      const response = await fetch(url, {
        method: body === undefined ? "GET" : "POST",
        headers: body === undefined
          ? { accept: "application/json" }
          : { accept: "application/json", "content-type": "application/json" },
        body: body === undefined ? undefined : JSON.stringify(body),
        signal: AbortSignal.timeout(timeoutMs),
      });
      if (!response.ok) throw new Error(`${url} answered ${response.status} ${response.statusText}`);
      return JSON.parse(await readCapped(response, MAX_FEED_BYTES, url));
    },
  };
}

export async function loadKev(fetcher: Fetcher): Promise<Kev> {
  const feed = (await fetcher.json(KEV_FEED)) as {
    dateReleased?: string;
    count?: number;
    vulnerabilities?: KevEntry[];
  };
  const byCve = new Map<string, KevEntry>();
  for (const entry of feed.vulnerabilities ?? []) {
    if (entry.cveID) byCve.set(entry.cveID.toUpperCase(), entry);
  }
  return { released: (feed.dateReleased ?? "unknown").slice(0, 10), count: byCve.size, byCve };
}

export function kevFromJson(document: unknown): Kev {
  const feed = document as { dateReleased?: string; vulnerabilities?: KevEntry[] };
  const byCve = new Map<string, KevEntry>();
  for (const entry of feed.vulnerabilities ?? []) byCve.set(entry.cveID.toUpperCase(), entry);
  return { released: (feed.dateReleased ?? "unknown").slice(0, 10), count: byCve.size, byCve };
}

/** OSV caps a batch; 100 keeps requests small enough to retry cheaply. */
const BATCH = 100;

/** Vulnerability ids per component, in the order the components were given. */
export async function queryOsv(fetcher: Fetcher, components: Component[]): Promise<string[][]> {
  const out: string[][] = [];
  for (let start = 0; start < components.length; start += BATCH) {
    const slice = components.slice(start, start + BATCH);
    const response = (await fetcher.json(OSV_BATCH, {
      queries: slice.map((component) => ({
        package: { name: component.name, ecosystem: component.ecosystem },
        version: component.version,
      })),
    })) as { results?: { vulns?: { id: string }[] }[] };

    for (let index = 0; index < slice.length; index += 1) {
      out.push((response.results?.[index]?.vulns ?? []).map((vuln) => vuln.id));
    }
  }
  return out;
}

export interface Vulnerability {
  id: string;
  aliases: string[];
  summary?: string;
  severity?: string;
  fixedIn: string[];
}

/** The batch endpoint returns ids only; the CVE aliases live on the record. */
export async function fetchVulnerabilities(fetcher: Fetcher, ids: string[]): Promise<Map<string, Vulnerability>> {
  const found = new Map<string, Vulnerability>();
  for (const id of ids) {
    const record = (await fetcher.json(OSV_VULN + encodeURIComponent(id))) as {
      id?: string;
      aliases?: string[];
      summary?: string;
      database_specific?: { severity?: string };
      affected?: { ranges?: { events?: { fixed?: string }[] }[] }[];
    };
    const fixedIn = new Set<string>();
    for (const affected of record.affected ?? []) {
      for (const range of affected.ranges ?? []) {
        for (const event of range.events ?? []) if (event.fixed) fixedIn.add(event.fixed);
      }
    }
    found.set(id, {
      id,
      aliases: record.aliases ?? [],
      summary: record.summary,
      severity: record.database_specific?.severity,
      fixedIn: [...fixedIn],
    });
  }
  return found;
}

/** CVE ids for a vulnerability record: its own id counts when it is already a CVE. */
export function cveIdsOf(vulnerability: Vulnerability): string[] {
  return [vulnerability.id, ...vulnerability.aliases]
    .filter((id) => /^CVE-\d{4}-\d+$/i.test(id))
    .map((id) => id.toUpperCase());
}
