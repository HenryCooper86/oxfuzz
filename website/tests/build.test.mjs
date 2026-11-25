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
    for (const name of [
      "build.mjs",
      "release.mjs",
      "locales.mjs",
      "src",
      "recordings",
    ])
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
  for (const name of [
    "build.mjs",
    "release.mjs",
    "locales.mjs",
    "src",
    "recordings",
  ])
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

test("the page lists what is new and says the desktop packages carry it", async () => {
  const root = await previewBuild();
  try {
    const repository = "https://github.com/HenryCooper86/oxfuzz";
    for (const edition of ["dist/index.html", "dist/zh/index.html"]) {
      const html = await readFile(join(root, edition), "utf8");
      assert.ok(html.includes('href="#whats-new"'), edition);
      const section = html.match(
        /<section[^>]*id="whats-new"[\s\S]*?<\/section>/,
      );
      assert.ok(section, edition);
      assert.equal((section[0].match(/<h3>/g) ?? []).length, 6, edition);
      for (const command of [
        "oxfuzz binary",
        "./scripts/pull-sandbox.sh",
        "/dev/kvm",
      ])
        assert.ok(section[0].includes(`<code>${command}</code>`), command);
      for (const path of [
        "/blob/main/CHANGELOG.md",
        "/blob/main/docs/guides/INSTALL.md",
      ])
        assert.ok(section[0].includes(`${repository}${path}`), path);
      // The desktop packages carry these features but not the command-line
      // tool; the section has to say where to get that.
      assert.match(section[0], /v\d+\.\d+\.\d+/);
    }
    const english = await readFile(join(root, "dist/index.html"), "utf8");
    assert.match(english, /in the desktop packages below from v\d+\.\d+\.\d+/);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("the GUI demos show four captioned videos whose files exist", async () => {
  const root = await previewBuild();
  try {
    for (const [edition, track] of [
      ["dist/index.html", "en"],
      ["dist/zh/index.html", "zh"],
    ]) {
      const html = await readFile(join(root, edition), "utf8");
      assert.ok(html.includes('href="#videos"'), edition);
      const section = html.match(/<section[^>]*id="videos"[\s\S]*?<\/section>/);
      assert.ok(section, edition);
      const videos = [...section[0].matchAll(/<video[\s\S]*?<\/video>/g)].map(
        (m) => m[0],
      );
      const names = videos.map(
        (v) => /src="\/demos\/([a-z0-9-]+)\.mp4"/.exec(v)?.[1],
      );
      assert.deepEqual(
        names,
        ["kernel-kvm", "setup", "campaign", "binary"],
        edition,
      );
      for (const [index, video] of videos.entries()) {
        const name = names[index];
        assert.ok(video.includes(`poster="/demos/${name}.jpg"`), name);
        assert.ok(video.includes(`src="/demos/${name}.${track}.vtt"`), name);
        assert.ok(video.includes(`srclang="${track}"`), name);
        assert.ok(
          /preload="none"/.test(video) && /\bcontrols\b/.test(video),
          name,
        );
        for (const file of [
          `${name}.mp4`,
          `${name}.jpg`,
          `${name}.${track}.vtt`,
        ])
          assert.ok(
            (await stat(join(root, "dist/demos", file))).size > 0,
            file,
          );
        const captions = await readFile(
          join(root, "dist/demos", `${name}.${track}.vtt`),
          "utf8",
        );
        assert.ok(captions.startsWith("WEBVTT"), name);
      }
      // Every clip says where and when it was recorded.
      assert.equal(
        (section[0].match(/class="video-meta"/g) ?? []).length,
        4,
        edition,
      );
    }
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("a demo file the page points at but the source lacks fails the build", async () => {
  const root = await mkdtemp(join(tmpdir(), "oxfuzz-site-"));
  try {
    const source = fileURLToPath(new URL("..", import.meta.url));
    for (const name of [
      "build.mjs",
      "release.mjs",
      "locales.mjs",
      "src",
      "recordings",
    ])
      await cp(join(source, name), join(root, name), { recursive: true });
    await rm(join(root, "src/demos/setup.zh.vtt"));
    const result = spawnSync(process.execPath, [
      join(root, "build.mjs"),
      "--preview",
    ]);
    assert.notEqual(result.status, 0);
    assert.match(String(result.stderr), /demos\/setup\.zh\.vtt/);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("terminal recordings are rendered from their transcripts, escaped and timed", async () => {
  const root = await previewBuild();
  try {
    for (const edition of ["dist/index.html", "dist/zh/index.html"]) {
      const html = await readFile(join(root, edition), "utf8");
      const screens = [
        ...html.matchAll(
          /<figure class="term" data-term[\s\S]*?<code>([\s\S]*?)<\/code>/g,
        ),
      ].map((match) => match[1]);
      assert.equal(screens.length, 2, edition);
      for (const screen of screens) {
        const lines = [
          ...screen.matchAll(
            /<span class="term-line ([a-z]+)" data-at="([0-9.]+)">(.*?)<\/span>/g,
          ),
        ];
        assert.ok(lines.length >= 6, edition);
        // A recording opens with the command that was typed.
        assert.equal(lines[0][1], "cmd");
        assert.match(lines[0][3], /^\$ oxfuzz /);
        // Lines appear in the order they were printed.
        const times = lines.map((line) => Number(line[2]));
        assert.deepEqual(
          times,
          [...times].sort((a, b) => a - b),
        );
        assert.equal(/<(?!\/?span)/.test(screen), false, "markup in output");
      }
    }
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("a recording with a line the build cannot read fails the build", async () => {
  const root = await previewBuild();
  try {
    await writeFile(
      join(root, "recordings/binary.term"),
      "@0|cmd|$ oxfuzz binary .\nthis line has no time\n",
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
