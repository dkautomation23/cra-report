/**
 * Working out what is actually in the product.
 *
 * The CRA makes you report an *actively exploited* vulnerability within 24
 * hours. You cannot do that without knowing your components, which is why the
 * SBOM obligation and the reporting obligation are really one obligation with
 * two deadlines.
 *
 * Two kinds of input are accepted. An SBOM, because that is the artefact the
 * regulation names and every ecosystem has a generator for it. And the lock
 * files themselves, because on the day you need this you will not want to
 * generate an SBOM first.
 */

import { readFileSync } from "node:fs";
import { basename } from "node:path";

/** OSV ecosystem names. https://ossf.github.io/osv-schema/#affectedpackage-field */
export type Ecosystem = "npm" | "PyPI" | "crates.io" | "Go" | "Maven" | "NuGet" | "RubyGems" | "Packagist";

export interface Component {
  name: string;
  version: string;
  ecosystem: Ecosystem;
}

const PURL_ECOSYSTEM: Record<string, Ecosystem> = {
  npm: "npm",
  pypi: "PyPI",
  cargo: "crates.io",
  golang: "Go",
  maven: "Maven",
  nuget: "NuGet",
  gem: "RubyGems",
  composer: "Packagist",
};

/**
 * A purl is percent-encoded, and `decodeURIComponent` throws on an escape that
 * is not valid - a lone `%`, or `%zz`. That comes from a build tool, not from
 * this code, and it must not end a report over a hundred other components.
 * The undecoded text is kept instead: visibly odd in the output, which is the
 * right outcome for a name that could not be read.
 */
function safeDecode(value: string): string {
  try {
    return decodeURIComponent(value);
  } catch {
    return value;
  }
}

/** `pkg:npm/%40scope/name@1.2.3` -> component. Returns null for a type we cannot map. */
export function fromPurl(purl: string): Component | null {
  const match = /^pkg:([^/]+)\/(.+)@([^?#]+)/.exec(purl);
  if (!match) return null;
  const ecosystem = PURL_ECOSYSTEM[match[1]!.toLowerCase()];
  if (!ecosystem) return null;
  const path = safeDecode(match[2]!);
  return {
    ecosystem,
    // Maven is the odd one: a purl writes group/artifact, OSV wants
    // group:artifact, and a lookup with the wrong separator silently finds
    // nothing - which reads exactly like "you are fine".
    name: ecosystem === "Maven" ? path.replace("/", ":") : path,
    version: safeDecode(match[3]!),
  };
}

function dedupe(components: Component[]): Component[] {
  const seen = new Map<string, Component>();
  for (const component of components) {
    if (!component.name || !component.version) continue;
    seen.set(`${component.ecosystem}|${component.name}|${component.version}`, component);
  }
  return [...seen.values()].sort((a, b) => a.name.localeCompare(b.name));
}

// --------------------------------------------------------------------------
// SBOM formats
// --------------------------------------------------------------------------

/**
 * A generator that writes `"components": {}` instead of `[]` produces a file
 * that still says CycloneDX at the top, so `load` hands it here. Iterating it
 * throws "object is not iterable", which tells the person holding a broken
 * SBOM nothing at all. Treating the wrong shape as no components lets the
 * report say "0 components" - which is true, and which they can act on.
 */
function asArray<T>(value: unknown): T[] {
  return Array.isArray(value) ? (value as T[]) : [];
}

export function fromCycloneDx(document: unknown): Component[] {
  const doc = document as { components?: unknown };
  const found: Component[] = [];
  for (const entry of asArray<{ purl?: string }>(doc?.components)) {
    const component = entry.purl ? fromPurl(entry.purl) : null;
    if (component) found.push(component);
  }
  return dedupe(found);
}

export function fromSpdx(document: unknown): Component[] {
  const doc = document as { packages?: unknown };
  const found: Component[] = [];
  for (const entry of asArray<{ externalRefs?: unknown }>(doc?.packages)) {
    for (const ref of asArray<{ referenceLocator?: string; referenceType?: string }>(entry?.externalRefs)) {
      if (ref?.referenceType !== "purl" || !ref.referenceLocator) continue;
      const component = fromPurl(ref.referenceLocator);
      if (component) found.push(component);
    }
  }
  return dedupe(found);
}

// --------------------------------------------------------------------------
// Lock files
// --------------------------------------------------------------------------

export function fromPackageLock(document: unknown): Component[] {
  const doc = document as { packages?: unknown };
  const packages = doc?.packages;
  const entries = packages && typeof packages === "object" && !Array.isArray(packages)
    ? Object.entries(packages as Record<string, { version?: string; link?: boolean }>)
    : [];
  const found: Component[] = [];
  for (const [path, entry] of entries) {
    // "" is the project itself; a link is a workspace pointer, not a release.
    if (!path || !entry || typeof entry !== "object" || entry.link || !entry.version) continue;
    const name = path.slice(path.lastIndexOf("node_modules/") + "node_modules/".length);
    if (!name) continue;
    found.push({ ecosystem: "npm", name, version: entry.version });
  }
  return dedupe(found);
}

export function fromCargoLock(text: string): Component[] {
  const found: Component[] = [];
  // Cargo.lock is TOML, but only ever this shape - and a TOML parser is a
  // dependency this tool does not otherwise need.
  for (const block of text.split(/\[\[package\]\]/).slice(1)) {
    const name = /^\s*name\s*=\s*"([^"]+)"/m.exec(block)?.[1];
    const version = /^\s*version\s*=\s*"([^"]+)"/m.exec(block)?.[1];
    if (name && version) found.push({ ecosystem: "crates.io", name, version });
  }
  return dedupe(found);
}

export function fromRequirements(text: string): Component[] {
  const found: Component[] = [];
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.split("#")[0]!.trim();
    if (!line || line.startsWith("-")) continue;
    // Only pinned requirements say what is actually installed. A range does
    // not, and guessing which version it resolved to would be a lie in a
    // document a regulator may read.
    const pinned = /^([A-Za-z0-9._-]+)\s*==\s*([A-Za-z0-9._+!-]+)/.exec(line);
    if (pinned) found.push({ ecosystem: "PyPI", name: pinned[1]!, version: pinned[2]! });
  }
  return dedupe(found);
}

export interface Loaded {
  components: Component[];
  /** What the file turned out to be, for the report's provenance line. */
  kind: string;
  unpinned: number;
}

export function load(path: string): Loaded {
  const text = readFileSync(path, "utf8");
  const name = basename(path).toLowerCase();

  if (name === "cargo.lock") {
    return { components: fromCargoLock(text), kind: "Cargo.lock", unpinned: 0 };
  }
  if (name.startsWith("requirements") && name.endsWith(".txt")) {
    const components = fromRequirements(text);
    const meaningful = text
      .split(/\r?\n/)
      .map((line) => line.split("#")[0]!.trim())
      .filter((line) => line && !line.startsWith("-")).length;
    return { components, kind: "requirements.txt", unpinned: meaningful - components.length };
  }

  let document: unknown;
  try {
    document = JSON.parse(text);
  } catch {
    throw new Error(`${path}: not JSON, and not a lock file this understands`);
  }

  const doc = document as Record<string, unknown>;
  if (doc.bomFormat === "CycloneDX") return { components: fromCycloneDx(doc), kind: "CycloneDX SBOM", unpinned: 0 };
  if (doc.spdxVersion) return { components: fromSpdx(doc), kind: "SPDX SBOM", unpinned: 0 };
  if (doc.lockfileVersion) return { components: fromPackageLock(doc), kind: "package-lock.json", unpinned: 0 };

  throw new Error(
    `${path}: unrecognised. Supported: CycloneDX or SPDX SBOM (JSON), package-lock.json, Cargo.lock, pinned requirements.txt`,
  );
}
