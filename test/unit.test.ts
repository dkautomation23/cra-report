import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, describe, it } from "node:test";

import {
  fromCargoLock,
  fromCycloneDx,
  fromPackageLock,
  fromPurl,
  fromRequirements,
  fromSpdx,
  load,
  type Component,
} from "../src/components.js";
import { assess, isExploited, summarise } from "../src/assess.js";
import { cveIdsOf, kevFromJson, queryOsv, fetchVulnerabilities, type Fetcher, type Vulnerability } from "../src/sources.js";
import { renderConsole, renderDraft, type Provenance } from "../src/report.js";
import { run } from "../src/cli.js";

const work = mkdtempSync(join(tmpdir(), "cra-report-"));
after(() => rmSync(work, { recursive: true, force: true }));
const FIXTURES = join(import.meta.dirname, "..", "..", "fixtures");

const KEV = kevFromJson(JSON.parse(readFileSync(join(FIXTURES, "kev-sample.json"), "utf8")));

function vuln(id: string, aliases: string[] = [], fixedIn: string[] = []): Vulnerability {
  return { id, aliases, fixedIn, summary: `${id} summary` };
}
function component(name: string, version: string): Component {
  return { name, version, ecosystem: "npm" };
}
const PROVENANCE: Provenance = {
  input: "package-lock.json",
  kind: "package-lock.json",
  kevReleased: "2026-09-16",
  unpinned: 0,
};

describe("reading what is in the product", () => {
  it("understands a purl, and ignores a type it cannot map", () => {
    assert.deepEqual(fromPurl("pkg:npm/lodash@4.17.15"), { ecosystem: "npm", name: "lodash", version: "4.17.15" });
    assert.deepEqual(fromPurl("pkg:cargo/serde@1.0.1"), { ecosystem: "crates.io", name: "serde", version: "1.0.1" });
    assert.equal(fromPurl("pkg:docker/library/nginx@1.25")?.name, undefined);
    assert.equal(fromPurl("not-a-purl"), null);
  });

  it("decodes a scoped npm package", () => {
    assert.equal(fromPurl("pkg:npm/%40babel/traverse@7.23.0")?.name, "@babel/traverse");
  });

  it("reads a CycloneDX SBOM", () => {
    const components = fromCycloneDx({
      bomFormat: "CycloneDX",
      components: [
        { purl: "pkg:npm/lodash@4.17.15" },
        { purl: "pkg:pypi/requests@2.19.0" },
        { name: "no-purl-here", version: "1.0.0" },
      ],
    });
    assert.deepEqual(components.map((c) => c.name), ["lodash", "requests"]);
    assert.equal(components[1]!.ecosystem, "PyPI");
  });

  it("reads an SPDX SBOM through its purl external refs", () => {
    const components = fromSpdx({
      spdxVersion: "SPDX-2.3",
      packages: [
        { name: "lodash", versionInfo: "4.17.15", externalRefs: [{ referenceType: "purl", referenceLocator: "pkg:npm/lodash@4.17.15" }] },
        { name: "no-refs", versionInfo: "1.0.0" },
      ],
    });
    assert.deepEqual(components, [{ ecosystem: "npm", name: "lodash", version: "4.17.15" }]);
  });

  it("a wrong-shaped SBOM is zero components, not a TypeError", () => {
    // Found by the fuzzer on its fourth run, from a valid package-lock.json:
    // `packages` as an object rather than a list made `for...of` throw
    // "object is not iterable", which tells the holder of a broken SBOM
    // nothing. Every reader now says zero instead of ending the run.
    assert.deepEqual(fromSpdx({ spdxVersion: "SPDX-2.3", packages: {} }), []);
    assert.deepEqual(fromSpdx({ packages: "nope" }), []);
    assert.deepEqual(fromSpdx({ packages: [{ externalRefs: "nope" }] }), []);
    assert.deepEqual(fromCycloneDx({ bomFormat: "CycloneDX", components: {} }), []);
    assert.deepEqual(fromPackageLock({ lockfileVersion: 3, packages: [] }), []);
    assert.deepEqual(fromPackageLock({ packages: "nope" }), []);
  });

  it("a purl with a broken percent-escape keeps its name instead of throwing", () => {
    // Also the fuzzer: decodeURIComponent throws URIError on a lone % or on
    // %zz, and that comes from whichever tool wrote the SBOM. One bad name
    // must not end a report covering a hundred other components.
    assert.equal(fromPurl("pkg:npm/%zz@1.0.0")?.name, "%zz");
    assert.equal(fromPurl("pkg:npm/name@1.0%")?.version, "1.0%");
    assert.equal(fromPurl("pkg:npm/%40scope/pkg@1.0.0")?.name, "@scope/pkg");
  });

  it("a KEV feed missing cveID loses that entry, not the run", () => {
    const kev = kevFromJson({
      dateReleased: "2026-09-01",
      vulnerabilities: [
        { cveID: "CVE-2021-44228" },
        { product: "no cve id here" },
        null,
      ],
    });
    assert.equal(kev.count, 1);
    assert.equal(kev.byCve.size, kev.count);
    assert.deepEqual(kevFromJson({ vulnerabilities: "nope" }).count, 0);
    assert.deepEqual(kevFromJson(42).count, 0);
  });

  it("reads package-lock.json and skips the project and its workspace links", () => {
    const components = fromPackageLock({
      lockfileVersion: 3,
      packages: {
        "": { version: "1.0.0" },
        "node_modules/lodash": { version: "4.17.15" },
        "node_modules/@babel/traverse": { version: "7.23.0" },
        "node_modules/my-workspace": { version: "1.0.0", link: true },
      },
    });
    assert.deepEqual(components.map((c) => c.name).sort(), ["@babel/traverse", "lodash"]);
  });

  it("reads Cargo.lock without a TOML parser", () => {
    const components = fromCargoLock(`
version = 4

[[package]]
name = "serde"
version = "1.0.219"

[[package]]
name = "time"
version = "0.1.44"
dependencies = ["libc"]
`);
    assert.deepEqual(components, [
      { ecosystem: "crates.io", name: "serde", version: "1.0.219" },
      { ecosystem: "crates.io", name: "time", version: "0.1.44" },
    ]);
  });

  it("reads only pinned requirements, because a range does not say what is installed", () => {
    const components = fromRequirements(`
# comment
requests==2.19.0
urllib3>=1.26        # a range: skipped on purpose
django==4.2.0  # trailing comment
-r other.txt
`);
    assert.deepEqual(components.map((c) => `${c.name}@${c.version}`), ["django@4.2.0", "requests@2.19.0"]);
  });

  it("counts the unpinned lines it skipped, so the report can say so", () => {
    const path = join(work, "requirements.txt");
    writeFileSync(path, "requests==2.19.0\nurllib3>=1.26\nflask\n", "utf8");
    const loaded = load(path);
    assert.equal(loaded.components.length, 1);
    assert.equal(loaded.unpinned, 2);
  });

  it("refuses a file it does not recognise instead of guessing", () => {
    const path = join(work, "mystery.json");
    writeFileSync(path, '{"hello":"world"}', "utf8");
    assert.throws(() => load(path), /unrecognised/);
  });

  it("de-duplicates and sorts, so two scans of the same tree match", () => {
    const components = fromCycloneDx({
      components: [{ purl: "pkg:npm/b@1.0.0" }, { purl: "pkg:npm/a@1.0.0" }, { purl: "pkg:npm/b@1.0.0" }],
    });
    assert.deepEqual(components.map((c) => c.name), ["a", "b"]);
  });
});

describe("what starts a 24-hour clock", () => {
  it("a CVE in the KEV catalogue is reportable", () => {
    const components = [component("lodash", "4.17.15")];
    const findings = assess(components, [["GHSA-x"]], new Map([["GHSA-x", vuln("GHSA-x", ["CVE-2021-44228"])]]), KEV);
    assert.equal(findings.length, 1);
    assert.equal(isExploited(findings[0]!), true);
    assert.equal(findings[0]!.kev[0]!.cveID, "CVE-2021-44228");
  });

  it("an advisory nobody is exploiting is not", () => {
    const findings = assess([component("left-pad", "1.0.0")], [["GHSA-y"]], new Map([["GHSA-y", vuln("GHSA-y", ["CVE-2099-0001"])]]), KEV);
    assert.equal(isExploited(findings[0]!), false);
  });

  it("matches when the advisory id is itself a CVE", () => {
    const findings = assess([component("x", "1")], [["CVE-2021-44228"]], new Map([["CVE-2021-44228", vuln("CVE-2021-44228")]]), KEV);
    assert.equal(isExploited(findings[0]!), true);
  });

  it("matches case-insensitively, because feeds disagree on case", () => {
    const findings = assess([component("x", "1")], [["GHSA-z"]], new Map([["GHSA-z", vuln("GHSA-z", ["cve-2021-44228"])]]), KEV);
    assert.equal(isExploited(findings[0]!), true);
  });

  it("a GHSA alias that is not a CVE is not mistaken for one", () => {
    assert.deepEqual(cveIdsOf(vuln("GHSA-a", ["GHSA-b", "SNYK-JS-1"])), []);
    assert.deepEqual(cveIdsOf(vuln("GHSA-a", ["CVE-2021-44228"])), ["CVE-2021-44228"]);
  });

  it("puts the exploited findings first, where the deadline is", () => {
    const components = [component("aaa-quiet", "1"), component("zzz-burning", "1")];
    const findings = assess(
      components,
      [["GHSA-quiet"], ["GHSA-burning"]],
      new Map([
        ["GHSA-quiet", vuln("GHSA-quiet", ["CVE-2099-0001"])],
        ["GHSA-burning", vuln("GHSA-burning", ["CVE-2021-44228"])],
      ]),
      KEV,
    );
    assert.equal(findings[0]!.component.name, "zzz-burning");
  });

  it("counts ransomware use separately", () => {
    const findings = assess([component("x", "1")], [["GHSA-r"]], new Map([["GHSA-r", vuln("GHSA-r", ["CVE-2023-4966"])]]), KEV);
    const summary = summarise([component("x", "1")], findings);
    assert.equal(summary.ransomware, 1, "CVE-2023-4966 is flagged as ransomware in the fixture");
  });

  it("a component with no advisories produces no findings", () => {
    assert.deepEqual(assess([component("clean", "1")], [[]], new Map(), KEV), []);
  });
});

describe("the output", () => {
  const exploited = assess(
    [component("lodash", "4.17.15")],
    [["GHSA-x"]],
    new Map([["GHSA-x", vuln("GHSA-x", ["CVE-2021-44228"], ["4.17.21"])]]),
    KEV,
  );

  it("says plainly when nothing is burning", () => {
    const text = renderConsole(summarise([component("a", "1")], []), PROVENANCE);
    assert.match(text, /No component carries a vulnerability that is known to be exploited/);
  });

  it("names the component, the CVE and the fix when something is", () => {
    const text = renderConsole(summarise([component("lodash", "4.17.15")], exploited), PROVENANCE);
    assert.match(text, /ACTIVELY EXPLOITED: 1 finding/);
    assert.match(text, /lodash 4\.17\.15/);
    assert.match(text, /CVE-2021-44228/);
    assert.match(text, /fixed in 4\.17\.21/);
  });

  it("warns about unpinned requirements rather than quietly ignoring them", () => {
    const text = renderConsole(summarise([], []), { ...PROVENANCE, unpinned: 3 });
    assert.match(text, /3 requirement\(s\) are not pinned/);
  });

  it("drafts the notification with the deadlines counted from now", () => {
    const now = new Date("2026-09-17T10:00:00.000Z");
    const draft = renderDraft(exploited, PROVENANCE, now);
    assert.match(draft, /2026-09-18T10:00:00\.000Z/, "24 hours");
    assert.match(draft, /2026-09-20T10:00:00\.000Z/, "72 hours");
    assert.match(draft, /CVE-2021-44228/);
    assert.match(draft, /TO COMPLETE/, "the parts only a person can answer are marked");
    assert.match(draft, /ENISA Single Reporting Platform/);
  });

  it("does not invent a notification when nothing is exploited", () => {
    const draft = renderDraft([], PROVENANCE, new Date("2026-09-17T10:00:00.000Z"));
    assert.match(draft, /No Article 14 notification is triggered/);
  });
});

describe("the whole run, against recorded responses", () => {
  /** Replays fixtures; a test that reached the network would fail on a plane. */
  function replay(): Fetcher {
    const osvBatch = JSON.parse(readFileSync(join(FIXTURES, "osv-batch.json"), "utf8"));
    const osvVulns = JSON.parse(readFileSync(join(FIXTURES, "osv-vulns.json"), "utf8")) as Record<string, unknown>;
    const kev = JSON.parse(readFileSync(join(FIXTURES, "kev-sample.json"), "utf8"));
    return {
      async json(url) {
        if (url.includes("querybatch")) return osvBatch;
        if (url.includes("/vulns/")) {
          const id = decodeURIComponent(url.split("/vulns/")[1]!);
          if (!(id in osvVulns)) throw new Error(`fixture has no vulnerability ${id}`);
          return osvVulns[id];
        }
        if (url.includes("known_exploited")) return kev;
        throw new Error(`unexpected url ${url}`);
      },
    };
  }

  it("exits 1 and writes a usable draft when a shipped component is being exploited", async () => {
    const draft = join(work, "early-warning.md");
    const json = join(work, "findings.json");
    let printed = "";

    const code = await run(
      [join(FIXTURES, "package-lock.json"), "--draft", draft, "--json", json],
      replay(),
      (text) => {
        printed += text;
      },
    );

    assert.equal(code, 1, "a reportable finding must fail the build");
    assert.match(printed, /ACTIVELY EXPLOITED/);
    assert.match(printed, /lodash/);

    const written = readFileSync(draft, "utf8");
    assert.match(written, /Article 14\(1\) early warning - DRAFT/);
    assert.match(written, /CVE-2021-44228/);

    const parsed = JSON.parse(readFileSync(json, "utf8"));
    assert.equal(parsed.reportable, 1);
    assert.equal(parsed.componentsRead, 3);
    assert.equal(parsed.findings.filter((f: { activelyExploited: boolean }) => f.activelyExploited).length, 1);
  });

  it("exits 0 when the only advisories are ones nobody is exploiting", async () => {
    const onlyQuiet = join(work, "quiet-lock.json");
    writeFileSync(
      onlyQuiet,
      JSON.stringify({ lockfileVersion: 3, packages: { "node_modules/quiet-dep": { version: "1.0.0" } } }),
      "utf8",
    );
    const code = await run([onlyQuiet, "--quiet"], replay(), () => {});
    assert.equal(code, 0);
  });

  it("exits 2 rather than pretending, when the input is not something it reads", async () => {
    const bad = join(work, "bad.json");
    writeFileSync(bad, '{"nope":true}', "utf8");
    await assert.rejects(run([bad], replay(), () => {}), /unrecognised/);
  });
});

describe("talking to the feeds", () => {
  it("splits a large component list into batches and keeps the order", async () => {
    const components: Component[] = Array.from({ length: 250 }, (_, i) => component(`pkg-${i}`, "1.0.0"));
    const seen: number[] = [];
    const fetcher: Fetcher = {
      async json(_url, body) {
        const queries = (body as { queries: unknown[] }).queries;
        seen.push(queries.length);
        return { results: queries.map((_, i) => ({ vulns: [{ id: `V${seen.length}-${i}` }] })) };
      },
    };
    const ids = await queryOsv(fetcher, components);
    assert.deepEqual(seen, [100, 100, 50]);
    assert.equal(ids.length, 250);
    assert.deepEqual(ids[0], ["V1-0"]);
    assert.deepEqual(ids[249], ["V3-49"]);
  });

  it("collects the fixed versions a record lists across its ranges", async () => {
    const fetcher: Fetcher = {
      async json() {
        return {
          id: "GHSA-q",
          aliases: ["CVE-2020-1"],
          affected: [
            { ranges: [{ events: [{ introduced: "0" }, { fixed: "1.2.3" }] }] },
            { ranges: [{ events: [{ fixed: "2.0.1" }] }] },
          ],
        };
      },
    };
    const found = await fetchVulnerabilities(fetcher, ["GHSA-q"]);
    assert.deepEqual(found.get("GHSA-q")!.fixedIn, ["1.2.3", "2.0.1"]);
    assert.deepEqual(found.get("GHSA-q")!.aliases, ["CVE-2020-1"]);
  });
});

describe("the first thing a stranger types", () => {
  const silent = () => {};

  for (const flag of ["--help", "-h"]) {
    it(`answers \`${flag}\` with the usage text and exit 0`, async () => {
      let printed = "";
      const code = await run([flag], undefined, (text) => {
        printed += text;
      });
      assert.equal(code, 0, "asking for help is not a mistake");
      assert.match(printed, /cra-report - /);
    });
  }

  it("exits 2 when nothing at all was named", async () => {
    const code = await run([], undefined, silent);
    assert.equal(code, 2, "an empty invocation is a usage error, not help");
  });
});
