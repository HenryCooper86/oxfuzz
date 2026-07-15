import { existsSync, readFileSync, readdirSync, statSync } from "node:fs";
import { resolve, join } from "node:path";

const distDir = resolve(process.argv[2] ?? "dist");
const manifestPath = join(distDir, ".vite", "manifest.json");

function budget(name, fallback) {
  const configured = Number(process.env[name] ?? fallback);
  if (!Number.isInteger(configured) || configured < 1) {
    throw new Error(`${name} must be a positive integer number of bytes`);
  }
  return configured;
}

const limits = {
  initial: budget("HF_GUI_INITIAL_JS_BUDGET", 1_200_000),
  total: budget("HF_GUI_TOTAL_JS_BUDGET", 4_700_000),
  chunk: budget("HF_GUI_MAX_CHUNK_BUDGET", 900_000),
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

const allFiles = javascriptFiles(distDir);
const initialBytes = [...initialFiles].reduce(
  (total, file) => total + statSync(join(distDir, file)).size,
  0,
);
const allAssets = allFiles.map((file) => ({ file, bytes: statSync(file).size }));
const totalBytes = allAssets.reduce((total, asset) => total + asset.bytes, 0);
const largest = allAssets.reduce(
  (current, asset) => (asset.bytes > current.bytes ? asset : current),
  { file: "", bytes: 0 },
);

const failures = [];
if (initialBytes > limits.initial) {
  failures.push(`initial JavaScript ${initialBytes} B exceeds ${limits.initial} B`);
}
if (totalBytes > limits.total) {
  failures.push(`total JavaScript ${totalBytes} B exceeds ${limits.total} B`);
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
  `Bundle budget passed: initial ${initialBytes}/${limits.initial} B, total ${totalBytes}/${limits.total} B, largest ${largest.bytes}/${limits.chunk} B`,
);
