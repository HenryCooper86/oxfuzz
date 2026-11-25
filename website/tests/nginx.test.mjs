import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";

const conf = await readFile(new URL("../nginx.conf", import.meta.url), "utf8");

test("the policy lets the page play its own demo videos and captions", () => {
  const policy = /Content-Security-Policy "([^"]+)"/.exec(conf)?.[1] ?? "";
  assert.match(policy, /default-src 'none'/);
  assert.match(policy, /media-src 'self'/);
});

test("demo captions are served as text/vtt", () => {
  const demos = /location \/demos\/ \{[\s\S]*?\n {4}\}/.exec(conf)?.[0] ?? "";
  assert.match(demos, /text\/vtt vtt;/);
  assert.match(demos, /video\/mp4 mp4;/);
});
