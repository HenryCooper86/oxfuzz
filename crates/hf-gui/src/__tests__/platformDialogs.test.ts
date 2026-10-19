// @vitest-environment jsdom
import { afterEach, expect, it, vi } from "vitest";
import { pickFile, pickFolder } from "../lib/platform";

const native = vi.hoisted(() => vi.fn());
vi.mock("@tauri-apps/api/core", () => ({ invoke: native }));

afterEach(() => {
  Reflect.deleteProperty(window, "__TAURI_INTERNALS__");
  vi.unstubAllEnvs();
});

it("retains native path selection when a desktop host uses the HTTP backend", async () => {
  Object.defineProperty(window, "__TAURI_INTERNALS__", { configurable: true, value: {} });
  vi.stubEnv("VITE_BACKEND", "http");
  native.mockImplementation(async (command: string) => command === "open_folder_dialog" ? "/local/project" : "/local/input.bin");
  expect(await pickFolder()).toBe("/local/project");
  expect(await pickFile()).toBe("/local/input.bin");
});
