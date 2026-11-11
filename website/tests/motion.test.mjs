import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import vm from "node:vm";

async function run({ reduced }) {
  const classes = new Set();
  const listeners = {};
  const document = {
    documentElement: { classList: { add: (name) => classes.add(name) } },
    addEventListener(name, fn) {
      listeners[name] = fn;
    },
  };
  const context = {
    document,
    matchMedia: () => ({ matches: reduced }),
    IntersectionObserver: class {},
  };
  context.window = context;
  vm.runInNewContext(
    await readFile(new URL("../src/motion.js", import.meta.url), "utf8"),
    context,
  );
  return { classes, listeners };
}

test("motion is opt-in: nothing is hidden or scheduled when reduced motion is requested", async () => {
  const page = await run({ reduced: true });
  assert.equal(page.classes.size, 0);
  assert.equal(page.listeners.DOMContentLoaded, undefined);
});

test("motion marks the document before first paint when it is allowed", async () => {
  const page = await run({ reduced: false });
  assert.ok(page.classes.has("motion"));
  assert.equal(typeof page.listeners.DOMContentLoaded, "function");
});
