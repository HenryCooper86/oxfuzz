import { expect, it } from "vitest";
import { engineDisplayName, harnessStatusLabelKey } from "../lib/harnessScope";

it("names engines the way the rest of the app does, whatever spelling the service used", () => {
  expect(engineDisplayName("AflPlusPlus")).toBe("AFL++");
  expect(engineDisplayName("afl++")).toBe("AFL++");
  expect(engineDisplayName("LibFuzzer")).toBe("libFuzzer");
  expect(engineDisplayName("honggfuzz")).toBe("honggfuzz");
  expect(engineDisplayName("syzkaller")).toBe("syzkaller");
  // An engine this build does not know is shown as received, not hidden.
  expect(engineDisplayName("go-native")).toBe("go-native");
});

it("does not call a smoke test that found crashes a pass", () => {
  expect(harnessStatusLabelKey("SmokePassed", true)).toBe("harness.statusLabel.smokePassed");
  expect(harnessStatusLabelKey("SmokePassed", false)).toBe("harness.statusLabel.smokeFindings");
  expect(harnessStatusLabelKey("Draft", false)).toBe("harness.statusLabel.draft");
  expect(harnessStatusLabelKey("Compiled", false)).toBe("harness.statusLabel.compiled");
  expect(harnessStatusLabelKey("Promoted", true)).toBe("harness.statusLabel.approved");
  expect(harnessStatusLabelKey("Failed", false)).toBe("harness.statusLabel.failed");
  expect(harnessStatusLabelKey("SomethingNew", false)).toBeNull();
});
