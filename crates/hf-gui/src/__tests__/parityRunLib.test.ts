import { expect, it } from "vitest";
import { straightQuotes } from "../lib/parityRun";
import {
  DEFAULT_RUN_OPTIONS,
  buildRunOptions,
  campaignRequest,
  engineStatusKey,
  runOptionsError,
} from "../lib/parityRun";

it("sends nothing for untouched run options", () => {
  expect(buildRunOptions(DEFAULT_RUN_OPTIONS, "afl++")).toEqual({});
});

it("maps touched run options to the wire shape, keeping the seed as text", () => {
  const built = buildRunOptions(
    { seed: "18446744073709551615", cpus: "2", timeoutMs: "500", resume: true, sanitizer: "address", cmplog: true, ai: "off" },
    "afl++",
  );
  expect(built).toEqual({
    seed: "18446744073709551615",
    options: { cpus: 2, timeoutMs: 500, resume: true, sanitizer: "address", cmplog: true, ai: "off" },
  });
});

it("drops the AFL++ only options for other engines", () => {
  const built = buildRunOptions({ ...DEFAULT_RUN_OPTIONS, resume: true, cmplog: true }, "libfuzzer");
  expect(built).toEqual({});
});

it("validates seed, cpus and timeout", () => {
  const limits = { maxCpus: 4 };
  expect(runOptionsError(DEFAULT_RUN_OPTIONS, limits)).toBeNull();
  expect(runOptionsError({ ...DEFAULT_RUN_OPTIONS, seed: "1.5" }, limits)).toBe("runOpts.seedInvalid");
  expect(runOptionsError({ ...DEFAULT_RUN_OPTIONS, seed: "18446744073709551616" }, limits)).toBe("runOpts.seedInvalid");
  expect(runOptionsError({ ...DEFAULT_RUN_OPTIONS, cpus: "5" }, limits)).toBe("runOpts.cpusInvalid");
  expect(runOptionsError({ ...DEFAULT_RUN_OPTIONS, cpus: "0" }, limits)).toBe("runOpts.cpusInvalid");
  expect(runOptionsError({ ...DEFAULT_RUN_OPTIONS, cpus: "9" }, { maxCpus: 4, showCpus: false })).toBeNull();
  expect(runOptionsError({ ...DEFAULT_RUN_OPTIONS, timeoutMs: "0" }, limits)).toBe("runOpts.timeoutInvalid");
});

it("builds a campaign request without cpus and with an optional target", () => {
  const request = campaignRequest(
    { project: "/p", target: "  ", engine: "afl++", lang: "c", durationSecs: 30, iterations: 2 },
    { ...DEFAULT_RUN_OPTIONS, cpus: "3", seed: "7", ai: "require" },
  );
  expect(request).toEqual({ project: "/p", engine: "afl++", lang: "c", durationSecs: 30, iterations: 2, seed: "7", ai: "require" });
});

it("maps engines to their preflight status flag", () => {
  expect(engineStatusKey("afl++")).toBe("aflplusplus");
  expect(engineStatusKey("jazzer-js")).toBe("jazzer_js");
  expect(engineStatusKey("go-native")).toBeNull();
});

it("turns the curly quotes macOS substitutes while typing back into straight ones", () => {
  expect(straightQuotes("\u201cFUZZ\u201d\nkw=\u201eGET\u201c")).toBe('"FUZZ"\nkw="GET"');
  expect(straightQuotes('"plain"')).toBe('"plain"');
});
