import { readFileSync } from "node:fs";
import { expect, it } from "vitest";
import { enExtra } from "../i18n.extra";
import { enGui } from "../i18n.gui";
import { enResults } from "../i18n.results";
import { enMutators } from "../i18n.mutators";
import { enBudgets } from "../i18n.budgets";

// One word per concept in what a user reads. The human gate is "approve"; the
// bounded sandbox check is a "smoke test"; the generated driver is a "harness".
// CLI, REST, and stored status names (`Promoted`, `promote`) are unchanged.
function englishCore(): Record<string, string> {
  const source = readFileSync(new URL("../i18n.tsx", import.meta.url), "utf8");
  const block = source.slice(source.indexOf("const en: Dict = {"), source.indexOf("const zh: Dict = {"));
  return Object.fromEntries([...block.matchAll(/^ {2}"([^"]+)": "((?:[^"\\]|\\.)*)",/gm)].map(m => [m[1], m[2]]));
}

// Automotive "promote a state signature" is a different operation.
const ALLOWED = /^automotive\.(stateCorpus|report)\./;

it("uses approve, smoke test, and harness instead of retired synonyms", () => {
  const all = { ...englishCore(), ...enGui, ...enResults, ...enMutators, ...enBudgets, ...enExtra };
  const offending = Object.entries(all)
    .filter(([key]) => !ALLOWED.test(key))
    .filter(([, text]) => /\bpromot|\bqualif|test driver/i.test(text))
    .map(([key, text]) => `${key}: ${text}`);
  expect(offending).toEqual([]);
});

it("avoids internal jargon a user cannot act on", () => {
  const all = { ...englishCore(), ...enGui, ...enResults, ...enMutators, ...enBudgets, ...enExtra };
  const jargon = /\badmission\b|legacy compile context|dispatch slots|terminal campaign|morning campaign|operator fuzzing policy|issued grants|^0 measured$|^Corpus absorb$|^Edge set$|^Trust report$|^Head run id$|^Base run id$/i;
  const offending = Object.entries(all).filter(([, text]) => jargon.test(text)).map(([key, text]) => `${key}: ${text}`);
  expect(offending).toEqual([]);
});
