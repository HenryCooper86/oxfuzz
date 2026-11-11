import { createHash } from "node:crypto";
import { createReadStream } from "node:fs";
import { cp, mkdir, readFile, stat, writeFile, rm } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { packages, validateRelease, version } from "./release.mjs";
import { locales } from "./locales.mjs";

const root = dirname(fileURLToPath(import.meta.url));
const preview = process.argv.includes("--preview");
const artifactIndex = process.argv.indexOf("--artifacts");
const artifactDir =
  artifactIndex >= 0 ? process.argv[artifactIndex + 1] : undefined;
if (!preview && !artifactDir)
  throw new Error(
    "Use --artifacts DIRECTORY for publication, or --preview for a local preview",
  );
if (preview && artifactDir)
  throw new Error("Preview and publication are separate modes");
const assets = [];
if (!preview) {
  for (const item of packages) {
    const path = join(resolve(artifactDir), item.name);
    const info = await stat(path);
    if (!info.isFile()) throw new Error(`Missing package: ${item.name}`);
    const hash = createHash("sha256");
    for await (const chunk of createReadStream(path)) hash.update(chunk);
    assets.push({
      name: item.name,
      size: info.size,
      sha256: hash.digest("hex"),
    });
  }
  validateRelease({ version, assets });
}
const dist = join(root, "dist");
const template = await readFile(join(root, "src/index.html"), "utf8");
const groups = ["macOS", "Linux", "Windows", "Sandbox"];

// Renders one language edition. A key the template or the build asks for and
// the locale lacks is an error, and so is a locale key nothing uses: both mean
// the page and its translations have drifted apart.
function render(language, strings) {
  const used = new Set();
  const t = (key) => {
    if (!(key in strings))
      throw new Error(`Locale "${language}" has no string for "${key}"`);
    used.add(key);
    return strings[key];
  };
  // Looked up in both modes, so a release build checks the preview wording too.
  const unavailable = t("dl_unavailable");
  const rows = groups
    .map(
      (platform) =>
        `<section class="download-row"><div><h3>${platform === "Sandbox" ? t("dl_sandbox_name") : platform}</h3><p>${t(`dl_${platform.toLowerCase()}`)}</p></div><div class="download-options">${packages
          .filter((p) => p.platform === platform)
          .map((item) => {
            const asset = assets.find((a) => a.name === item.name);
            return asset
              ? `<a class="download" href="/downloads/v${version}/${item.name}" download><span>${item.label}<small>${item.format} · ${(asset.size / 1048576).toFixed(1)} MB</small></span><span aria-hidden="true">↓</span></a>`
              : `<span class="download unavailable">${item.label}<small>${unavailable}</small></span>`;
          })
          .join("")}</div></section>`,
    )
    .join("");
  const notice = `<p class="preview">${t("dl_preview")}</p>`;
  const pending = `<p>${t("verify_pending")}</p>`;
  const checksums = `<a href="/downloads/v${version}/SHA256SUMS.txt">${t("verify_sums")}</a> · <a href="/release.json">${t("verify_manifest")}</a>`;
  const html = template
    .replace(/\{\{([a-z0-9_]+)\}\}/g, (_, key) => t(key))
    .replace("<!-- DOWNLOADS -->", rows)
    .replace("<!-- PREVIEW -->", preview ? notice : "")
    .replace("<!-- CHECKSUMS -->", preview ? pending : checksums)
    .replaceAll("{{VERSION}}", version);
  const unused = Object.keys(strings).filter((key) => !used.has(key));
  if (unused.length)
    throw new Error(`Locale "${language}" has unused strings: ${unused}`);
  return html;
}
// Render every edition before touching dist, so a broken locale changes nothing.
const editions = Object.entries(locales).map(([language, strings]) => ({
  path: language === "en" ? "index.html" : join(language, "index.html"),
  html: render(language, strings),
}));
// Validate every input before replacing the generated directory.
await rm(dist, { recursive: true, force: true });
await mkdir(dist, { recursive: true });
await cp(join(root, "src"), dist, { recursive: true });
await writeFile(
  join(dist, "release.json"),
  JSON.stringify(
    {
      version,
      preview,
      assets: preview ? [] : validateRelease({ version, assets }),
    },
    null,
    2,
  ) + "\n",
);
for (const edition of editions) {
  await mkdir(dirname(join(dist, edition.path)), { recursive: true });
  await writeFile(join(dist, edition.path), edition.html);
}
if (!preview) {
  const destination = join(dist, "downloads", `v${version}`);
  await mkdir(destination, { recursive: true });
  for (const asset of assets)
    await cp(
      join(resolve(artifactDir), asset.name),
      join(destination, asset.name),
    );
  await writeFile(
    join(destination, "SHA256SUMS.txt"),
    assets.map((a) => `${a.sha256}  ${a.name}\n`).join(""),
  );
}
console.log(`${preview ? "Preview" : "Release"} built: ${dist}`);
