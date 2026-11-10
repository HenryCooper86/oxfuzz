import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import vm from "node:vm";

async function setup({ saved, blocked = false, dark = false } = {}) {
  const handlers = {};
  const attributes = {};
  const button = {
    hidden: true,
    setAttribute(k, v) {
      attributes[k] = v;
    },
    addEventListener(k, fn) {
      handlers[k] = fn;
    },
  };
  const root = { dataset: {} };
  const media = {
    matches: dark,
    addEventListener(k, fn) {
      handlers.media = fn;
    },
  };
  const storage = {
    getItem() {
      if (blocked) throw Error("blocked");
      return saved;
    },
    setItem(k, v) {
      if (blocked) throw Error("blocked");
      saved = v;
    },
  };
  const listeners = {};
  const views = ["dashboard", "harness", "run-history"].map((id) => ({
    id,
    hidden: id !== "dashboard",
  }));
  const selectors = views.map((view) => ({
    dataset: { view: view.id },
    setAttribute(k, v) {
      this[k] = v;
    },
    addEventListener(k, fn) {
      this[k] = fn;
    },
  }));
  const document = {
    documentElement: root,
    addEventListener(k, fn) {
      listeners[k] = fn;
    },
    getElementById(id) {
      return id === "theme-toggle" ? button : views.find((v) => v.id === id);
    },
    querySelectorAll() {
      return selectors;
    },
  };
  vm.runInNewContext(
    await readFile(new URL("../src/appearance.js", import.meta.url), "utf8"),
    { document, localStorage: storage, matchMedia: () => media },
  );
  listeners.DOMContentLoaded();
  return {
    root,
    button,
    attributes,
    handlers,
    media,
    selectors,
    views,
    saved: () => saved,
  };
}
test("theme cycles System to Dark to Light to System, persists and labels next action", async () => {
  const app = await setup();
  assert.equal(app.root.dataset.theme, "light");
  assert.match(app.attributes["aria-label"], /System.*Dark/);
  app.handlers.click();
  assert.equal(app.root.dataset.theme, "dark");
  assert.equal(app.saved(), "dark");
  app.handlers.click();
  assert.equal(app.root.dataset.theme, "light");
  assert.equal(app.saved(), "light");
  app.handlers.click();
  assert.equal(app.saved(), "system");
  assert.equal(app.button.hidden, false);
});
test("System follows OS changes while explicit preference remains stable", async () => {
  const app = await setup({ saved: "system", dark: true });
  assert.equal(app.root.dataset.theme, "dark");
  app.media.matches = false;
  app.handlers.media();
  assert.equal(app.root.dataset.theme, "light");
  app.handlers.click();
  app.handlers.media();
  assert.equal(app.root.dataset.theme, "dark");
});
test("saved theme restores and invalid or blocked storage falls back to System", async () => {
  assert.equal((await setup({ saved: "dark" })).root.dataset.theme, "dark");
  for (const config of [
    { saved: "unexpected", dark: true },
    { blocked: true, dark: true },
  ]) {
    const app = await setup(config);
    assert.equal(app.root.dataset.theme, "dark");
    assert.match(app.attributes["aria-label"], /System/);
    app.handlers.click();
  }
});
test("gallery selection exposes exactly the requested screenshot and pressed control", async () => {
  const app = await setup();
  app.selectors[1].click();
  assert.deepEqual(
    app.views.map((v) => v.hidden),
    [true, false, true],
  );
  assert.deepEqual(
    app.selectors.map((v) => v["aria-pressed"]),
    ["false", "true", "false"],
  );
});
