import test from "node:test";
import assert from "node:assert/strict";
import { validateRelease } from "../release.mjs";
const asset = {
  name: "oxfuzz_0.9.12_aarch64.dmg",
  size: 42,
  sha256: "a".repeat(64),
};
const release = () => ({ version: "0.9.12", assets: [asset] });
test("accepts verified desktop assets and derives same-origin download paths", () => {
  assert.equal(
    validateRelease(release())[0].url,
    "/downloads/v0.9.12/oxfuzz_0.9.12_aarch64.dmg",
  );
});
test("rejects unavailable or malformed download evidence", () => {
  for (const patch of [
    { size: 0 },
    { size: -1 },
    { sha256: "unknown" },
    { name: "../secret" },
    { name: "https://github.com/private/file" },
    { name: "oxfuzz_0.9.3_aarch64.dmg" },
  ]) {
    assert.throws(() =>
      validateRelease({ ...release(), assets: [{ ...asset, ...patch }] }),
    );
  }
  assert.throws(() => validateRelease({ ...release(), assets: [] }));
  assert.throws(() => validateRelease({ ...release(), version: "../private" }));
});
test("rejects duplicate assets", () => {
  assert.throws(() =>
    validateRelease({ ...release(), assets: [asset, asset] }),
  );
});
test("rejects Windows installers, which are not shipped", () => {
  for (const name of [
    "oxfuzz_0.9.12_x64_en-US.msi",
    "oxfuzz_0.9.12_x64-setup.exe",
  ])
    assert.throws(() =>
      validateRelease({ ...release(), assets: [{ ...asset, name }] }),
    );
});
