import { existsSync, readFileSync, readdirSync, statSync } from "node:fs";
import { resolve, join, relative } from "node:path";
import { normalizeAssetPath } from "./bundle-budget-paths.mjs";

const distDir = resolve(process.argv[2] ?? "dist");
const manifestPath = join(distDir, ".vite", "manifest.json");

function budget(name, fallback) {
  const configured = Number(process.env[name] ?? fallback);
  if (!Number.isInteger(configured) || configured < 1) {
    throw new Error(`${name} must be a positive integer number of bytes`);
  }
  return configured;
}

// App and vendor are budgeted apart rather than as one total. A single total
// cannot say which of the two moved, and in this app the dependencies are the
// larger share by far: a combined budget fires on a diagram library shipping
// another parser long before it fires on our own code growing, which is the
// thing a budget is supposed to catch.
const limits = {
  initial: budget("HF_GUI_INITIAL_JS_BUDGET", 1_200_000),
  chunk: budget("HF_GUI_MAX_CHUNK_BUDGET", 900_000),
  app: budget("HF_GUI_APP_JS_BUDGET", 1_400_000),
  vendor: budget("HF_GUI_VENDOR_JS_BUDGET", 3_700_000),
};

if (!existsSync(manifestPath)) {
  console.error(`Bundle budget failed: missing Vite manifest at ${manifestPath}`);
  process.exit(1);
}

const manifest = JSON.parse(readFileSync(manifestPath, "utf8"));
const entries = Object.values(manifest).filter((item) => item.isEntry);
if (entries.length === 0) {
  console.error("Bundle budget failed: the Vite manifest has no entry module");
  process.exit(1);
}

function staticFiles(item, seenKeys = new Set()) {
  const files = new Set();
  if (item.file?.endsWith(".js")) files.add(item.file);
  for (const key of item.imports ?? []) {
    if (seenKeys.has(key)) continue;
    seenKeys.add(key);
    const imported = manifest[key];
    if (!imported) continue;
    for (const file of staticFiles(imported, seenKeys)) files.add(file);
  }
  return files;
}

const initialFiles = new Set();
for (const entry of entries) {
  for (const file of staticFiles(entry)) initialFiles.add(file);
}

function javascriptFiles(dir) {
  return readdirSync(dir, { withFileTypes: true }).flatMap((entry) => {
    const path = join(dir, entry.name);
    if (entry.isDirectory()) return javascriptFiles(path);
    return entry.name.endsWith(".js") ? [path] : [];
  });
}

/**
 * Every chunk our own module graph produces: the entry, everything it imports
 * statically, and the views we lazy-load.
 *
 * A dynamic import into `node_modules/` is not followed. That is the boundary:
 * a dependency's own lazily-loaded chunk is weight we did not write and cannot
 * shrink by editing our code, so it is not measured against the budget that
 * bounds our code. A chunk shared with a dependency stays on our side, which
 * keeps the split conservative in the direction that matters.
 */
function appFiles() {
  const files = new Set();
  const seen = new Set();
  const walk = (key) => {
    if (seen.has(key)) return;
    seen.add(key);
    const item = manifest[key];
    if (!item) return;
    if (item.file?.endsWith(".js")) files.add(item.file);
    for (const next of item.imports ?? []) walk(next);
    for (const next of item.dynamicImports ?? []) {
      if (isAppModule(next)) walk(next);
    }
  };
  for (const key of Object.keys(manifest)) {
    if (isAppModule(key)) walk(key);
  }
  return files;
}

/** Whether a manifest key names a module from this repository. */
function isAppModule(key) {
  return key.startsWith("src/");
}

const allFiles = javascriptFiles(distDir);
const initialBytes = [...initialFiles].reduce(
  (total, file) => total + statSync(join(distDir, file)).size,
  0,
);
const ours = appFiles();
const allAssets = allFiles.map((file) => ({
  file,
  bytes: statSync(file).size,
  // `javascriptFiles` yields paths under `distDir`; manifest `file` values are
  // relative to it, so membership is tested on the relative form.
  app: ours.has(normalizeAssetPath(relative(distDir, file))),
}));
const appBytes = allAssets
  .filter((asset) => asset.app)
  .reduce((total, asset) => total + asset.bytes, 0);
const vendorBytes = allAssets
  .filter((asset) => !asset.app)
  .reduce((total, asset) => total + asset.bytes, 0);
const largest = allAssets.reduce(
  (current, asset) => (asset.bytes > current.bytes ? asset : current),
  { file: "", bytes: 0 },
);

const failures = [];
if (initialBytes > limits.initial) {
  failures.push(`initial JavaScript ${initialBytes} B exceeds ${limits.initial} B`);
}
if (appBytes > limits.app) {
  failures.push(`app JavaScript ${appBytes} B exceeds ${limits.app} B`);
}
if (vendorBytes > limits.vendor) {
  failures.push(`vendor JavaScript ${vendorBytes} B exceeds ${limits.vendor} B`);
}
if (largest.bytes > limits.chunk) {
  failures.push(
    `largest JavaScript chunk ${largest.bytes} B exceeds ${limits.chunk} B (${largest.file})`,
  );
}

if (failures.length > 0) {
  for (const failure of failures) console.error(`Bundle budget failed: ${failure}`);
  process.exit(1);
}

console.log(
  `Bundle budget passed: initial ${initialBytes}/${limits.initial} B, ` +
    `largest ${largest.bytes}/${limits.chunk} B, ` +
    `app ${appBytes}/${limits.app} B, vendor ${vendorBytes}/${limits.vendor} B`,
);
