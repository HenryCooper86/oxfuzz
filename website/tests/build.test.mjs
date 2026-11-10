import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, cp, mkdir, readFile, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { execFileSync, spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { packages } from "../release.mjs";

test("publication requires a complete package set and hashes the served bytes", async () => {
  const root = await mkdtemp(join(tmpdir(), "oxfuzz-site-"));
  try {
    const source = fileURLToPath(new URL("..", import.meta.url));
    for (const name of ["build.mjs", "release.mjs", "src"])
      await cp(join(source, name), join(root, name), { recursive: true });
    const artifacts = join(root, "assets");
    await mkdir(artifacts);
    const build = join(root, "build.mjs");
    assert.notEqual(
      spawnSync(process.execPath, [build, "--artifacts", artifacts]).status,
      0,
    );
    for (const item of packages)
      await writeFile(join(artifacts, item.name), "abc");
    execFileSync(process.execPath, [build, "--artifacts", artifacts]);
    const manifest = JSON.parse(
      await readFile(join(root, "dist/release.json"), "utf8"),
    );
    assert.equal(manifest.preview, false);
    assert.equal(manifest.assets.length, packages.length);
    for (const item of manifest.assets) {
      assert.equal(
        item.sha256,
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
      );
      assert.equal(item.size, 3);
      assert.equal(await readFile(join(root, "dist", item.url), "utf8"), "abc");
    }
    const html = await readFile(join(root, "dist/index.html"), "utf8");
    assert.equal((html.match(/ download>/g) ?? []).length, packages.length);
    assert.equal(html.includes("not yet available"), false);
    await writeFile(join(artifacts, packages[0].name), "");
    assert.notEqual(
      spawnSync(process.execPath, [build, "--artifacts", artifacts]).status,
      0,
    );
    assert.equal(await readFile(join(root, "dist/index.html"), "utf8"), html);
    execFileSync(process.execPath, [build, "--preview"]);
    const preview = await readFile(join(root, "dist/index.html"), "utf8");
    assert.equal(preview.includes(" download>"), false);
    assert.equal(
      JSON.parse(await readFile(join(root, "dist/release.json"), "utf8"))
        .preview,
      true,
    );
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
