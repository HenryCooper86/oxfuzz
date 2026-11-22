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

// A page with one terminal recording of three lines, and timers the test fires.
async function recording() {
  const classes = new Set();
  const listeners = {};
  const timers = [];
  const line = (at) => {
    const names = new Set();
    return {
      dataset: { at: String(at) },
      names,
      classList: {
        add: (name) => names.add(name),
        remove: (name) => names.delete(name),
      },
    };
  };
  const lines = [line(0), line(1.5), line(3)];
  const replay = {
    hidden: true,
    addEventListener(name, fn) {
      this.click = fn;
    },
  };
  const figure = {
    querySelectorAll: () => lines,
    querySelector: () => replay,
  };
  let observed;
  const context = {
    document: {
      documentElement: { classList: { add: (name) => classes.add(name) } },
      addEventListener(name, fn) {
        listeners[name] = fn;
      },
      querySelectorAll: (selector) =>
        selector === "[data-term]" ? [figure] : [],
    },
    matchMedia: () => ({ matches: false }),
    IntersectionObserver: class {
      constructor(callback) {
        observed = callback;
      }
      observe() {}
      unobserve() {}
    },
    setTimeout: (fn, delay) => timers.push({ fn, delay }),
    clearTimeout: () => {},
  };
  context.window = context;
  vm.runInNewContext(
    await readFile(new URL("../src/motion.js", import.meta.url), "utf8"),
    context,
  );
  listeners.DOMContentLoaded();
  return { lines, replay, timers, figure, show: () => observed };
}

test("a terminal recording plays its lines in order once it scrolls into view", async () => {
  const page = await recording();
  // Nothing is hidden before the recording is on screen.
  assert.ok(page.lines.every((line) => !line.names.has("pending")));
  page.show()([{ isIntersecting: true, target: page.figure }]);
  assert.ok(page.lines.every((line) => line.names.has("pending")));
  assert.deepEqual(
    page.timers.map((timer) => timer.delay),
    [0, 1500, 3000],
  );
  page.timers[0].fn();
  assert.equal(page.lines[0].names.has("pending"), false);
  assert.equal(page.lines[2].names.has("pending"), true);
  for (const timer of page.timers) timer.fn();
  assert.ok(page.lines.every((line) => !line.names.has("pending")));
  assert.equal(page.replay.hidden, false);
});
