import { createHash } from "node:crypto";
import { createReadStream } from "node:fs";
import { cp, mkdir, readFile, stat, writeFile, rm } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { packages, validateRelease, version } from "./release.mjs";

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
// Validate every input before replacing the generated directory.
const dist = join(root, "dist");
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
let html = await readFile(join(root, "src/index.html"), "utf8");
const groups = ["macOS", "Linux", "Windows", "Sandbox"];
const rows = groups
  .map(
    (platform) =>
      `<section class="download-row"><div><h3>${platform}</h3><p>${{ macOS: "Apple silicon or Intel. Ad-hoc signed; not notarized.", Linux: "x86_64 desktop. Docker Engine required.", Windows: "64-bit Windows. Unsigned installers. Docker Desktop with WSL 2.", Sandbox: "Build the isolated engine environment locally. Docker required." }[platform]}</p></div><div class="download-options">${packages
        .filter((p) => p.platform === platform)
        .map((item) => {
          const asset = assets.find((a) => a.name === item.name);
          return asset
            ? `<a class="download" href="/downloads/v${version}/${item.name}" download><span>${item.label}<small>${item.format} · ${(asset.size / 1048576).toFixed(1)} MB</small></span><span aria-hidden="true">↓</span></a>`
            : `<span class="download unavailable">${item.label}<small>Candidate build · not yet available</small></span>`;
        })
        .join("")}</div></section>`,
  )
  .join("");
html = html
  .replace("<!-- DOWNLOADS -->", rows)
  .replaceAll("{{VERSION}}", version)
  .replace(
    "<!-- PREVIEW -->",
    preview
      ? '<p class="preview">Release verification is in progress. Downloads will be enabled after the checks finish.</p>'
      : "",
  )
  .replace(
    "<!-- CHECKSUMS -->",
    preview
      ? "<p>Checksums appear with the verified release.</p>"
      : '<a href="/downloads/v' +
          version +
          '/SHA256SUMS.txt">Download SHA256SUMS.txt</a> · <a href="/release.json">Release manifest</a>',
  );
await writeFile(join(dist, "index.html"), html);
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
