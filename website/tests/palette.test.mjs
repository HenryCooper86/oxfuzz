import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";

// The site shows the desktop app, so its palette follows the app's design
// tokens (crates/hf-gui/src/styles/index.css). Site token -> app token.
const MAP = {
  "--bg": "--surface-primary",
  "--surface": "--surface-secondary",
  "--raised": "--surface-tertiary",
  "--text": "--text-primary",
  "--muted": "--text-secondary",
  "--accent": "--accent",
  "--accent-hover": "--accent-hover",
  "--on-accent": "--accent-contrast",
  "--green": "--success",
};

function block(css, selector) {
  const start = css.indexOf(`${selector} {`);
  assert.notEqual(start, -1, `missing ${selector}`);
  return css.slice(start, css.indexOf("\n}", start));
}

function value(text, token) {
  const match = text.match(new RegExp(`\\n\\s*${token}:\\s*([^;]+);`));
  assert.ok(match, `missing ${token}`);
  return match[1].trim().toLowerCase();
}

const site = await readFile(new URL("../src/style.css", import.meta.url), "utf8");
const app = await readFile(new URL("../../crates/hf-gui/src/styles/index.css", import.meta.url), "utf8");

for (const [theme, siteSelector, appSelector] of [
  ["light", ":root", '[data-theme="light"]'],
  ["dark", ':root[data-theme="dark"]', ':root,\n[data-theme="dark"]'],
]) {
  test(`${theme} site palette follows the app tokens`, () => {
    const siteBlock = block(site, siteSelector);
    const appBlock = block(app, appSelector);
    for (const [siteToken, appToken] of Object.entries(MAP)) {
      assert.equal(value(siteBlock, siteToken), value(appBlock, appToken), `${theme} ${siteToken}`);
    }
  });
}

test("the system dark scheme repeats the explicit dark palette", () => {
  const explicit = block(site, ':root[data-theme="dark"]');
  const system = block(site, "  :root:not([data-theme])");
  for (const token of Object.keys(MAP)) {
    assert.equal(value(system, token), value(explicit, token), token);
  }
});
