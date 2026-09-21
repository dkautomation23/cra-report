/**
 * The input to this tool is a file someone else generated: an SBOM from a
 * build system, a lock file from a package manager, a KEV feed from CISA. A
 * report that a regulator may read must not become a stack trace because a
 * field was a number where a string was expected.
 *
 * So the property is not "the components are right" - the suite checks that.
 * It is that every one of these readers returns a well-formed answer for any
 * bytes at all, and never invents a component out of nothing.
 */
import {
  fromCargoLock,
  fromCycloneDx,
  fromPackageLock,
  fromPurl,
  fromRequirements,
  fromSpdx,
} from "../dist/src/components.js";
import { kevFromJson } from "../dist/src/sources.js";

function checkComponents(where, components) {
  if (!Array.isArray(components)) {
    throw new Error(`${where} must return an array, got ${typeof components}`);
  }
  for (const component of components) {
    if (typeof component.name !== "string" || component.name === "") {
      throw new Error(`${where} produced a component with no name`);
    }
    if (typeof component.version !== "string") {
      throw new Error(`${where} produced ${component.name} with a non-string version`);
    }
  }
}

export function fuzz(data) {
  const text = data.toString("utf8");

  checkComponents("fromCargoLock", fromCargoLock(text));
  checkComponents("fromRequirements", fromRequirements(text));

  const purl = fromPurl(text.slice(0, 300));
  if (purl !== null && typeof purl.name !== "string") {
    throw new Error("fromPurl returned something that is not a component");
  }

  // The JSON readers take a parsed document, so anything that is not JSON is
  // simply not their case - but a document that parses to a number, a string
  // or a truncated shape very much is.
  let document;
  try {
    document = JSON.parse(text);
  } catch {
    return;
  }

  checkComponents("fromCycloneDx", fromCycloneDx(document));
  checkComponents("fromSpdx", fromSpdx(document));
  checkComponents("fromPackageLock", fromPackageLock(document));

  const kev = kevFromJson(document);
  if (!(kev.byCve instanceof Map)) {
    throw new Error("kevFromJson must always return a map of entries");
  }
  if (kev.count !== kev.byCve.size) {
    throw new Error(`kev count ${kev.count} disagrees with ${kev.byCve.size} entries`);
  }
}
