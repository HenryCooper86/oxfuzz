import test from "node:test";
import assert from "node:assert/strict";
import {
  mkdtemp,
  cp,
  mkdir,
  readFile,
  writeFile,
  rm,
  stat,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { execFileSync, spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { packages } from "../release.mjs";
import { locales } from "../locales.mjs";

test("publication requires a complete package set and hashes the served bytes", async () => {
  const root = await mkdtemp(join(tmpdir(), "oxfuzz-site-"));
  try {
    const source = fileURLToPath(new URL("..", import.meta.url));
    for (const name of ["build.mjs", "release.mjs", "locales.mjs", "src"])
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

async function previewBuild() {
  const root = await mkdtemp(join(tmpdir(), "oxfuzz-site-"));
  const source = fileURLToPath(new URL("..", import.meta.url));
  for (const name of ["build.mjs", "release.mjs", "locales.mjs", "src"])
    await cp(join(source, name), join(root, name), { recursive: true });
  execFileSync(process.execPath, [join(root, "build.mjs"), "--preview"]);
  return root;
}

test("the page links the source repository and invites contributions", async () => {
  const root = await previewBuild();
  try {
    const html = await readFile(join(root, "dist/index.html"), "utf8");
    const repository = "https://github.com/HenryCooper86/oxfuzz";
    // Header, hero, the contribute section and the footer all reach GitHub.
    assert.ok(html.split(`href="${repository}"`).length - 1 >= 4);
    for (const path of [
      "/issues/new/choose",
      "/blob/main/CONTRIBUTING.md",
      "/blob/main/SECURITY.md",
      "/blob/main/LICENSE",
    ])
      assert.ok(html.includes(`${repository}${path}`), path);
    assert.match(html, /open source/i);
    assert.match(html, /MIT license/);
    assert.match(html, /Any improvement is welcome/);
    // The old page told visitors they did not need GitHub at all.
    assert.equal(html.includes("do not require a GitHub account"), false);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("English and Chinese editions carry the same keys, all of them filled in", () => {
  assert.deepEqual(
    Object.keys(locales.zh).sort(),
    Object.keys(locales.en).sort(),
  );
  for (const [language, strings] of Object.entries(locales))
    for (const [key, value] of Object.entries(strings))
      assert.ok(String(value).trim().length > 0, `${language}.${key}`);
});

test("both editions build without unresolved placeholders and link each other", async () => {
  const root = await previewBuild();
  try {
    const english = await readFile(join(root, "dist/index.html"), "utf8");
    const chinese = await readFile(join(root, "dist/zh/index.html"), "utf8");
    for (const html of [english, chinese]) {
      assert.equal(html.includes("{{"), false);
      assert.equal(html.includes("<!-- "), false);
      assert.match(html, /hreflang="en" href="\/"/);
      assert.match(html, /hreflang="zh-CN" href="\/zh\/"/);
    }
    assert.match(english, /<html lang="en"/);
    assert.match(chinese, /<html lang="zh-CN"/);
    assert.match(english, /<a[^>]+href="\/zh\/"[^>]*lang="zh-CN"/);
    assert.match(chinese, /<a[^>]+href="\/"[^>]*lang="en"/);
    assert.match(chinese, /开源/);
    assert.match(chinese, /MIT/);
    // Navigation inside the Chinese edition stays in the Chinese edition.
    assert.match(chinese, /class="brand" href="\/zh\/"/);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("a locale that misses a template key fails the build", async () => {
  const root = await previewBuild();
  try {
    const path = join(root, "locales.mjs");
    const source = await readFile(path, "utf8");
    await writeFile(
      path,
      source.replace(/\n\s*hero_title:/, "\n    hero_title_gone:"),
    );
    assert.notEqual(
      spawnSync(process.execPath, [join(root, "build.mjs"), "--preview"])
        .status,
      0,
    );
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("the workflow gallery shows four captures that exist, and a recording", async () => {
  const root = await previewBuild();
  try {
    const html = await readFile(join(root, "dist/index.html"), "utf8");
    const views = [...html.matchAll(/data-view="([a-z-]+)"/g)].map((m) => m[1]);
    assert.deepEqual(views, ["discover", "harness", "run", "triage"]);
    for (const view of views) {
      assert.ok(html.includes(`<figure id="${view}"`), view);
      await stat(join(root, "dist/screenshots", `${view}.jpg`));
    }
    assert.ok(html.includes('src="/screenshots/oxfuzz-at-work.gif"'));
    await stat(join(root, "dist/screenshots/oxfuzz-at-work.gif"));
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
