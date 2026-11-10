// @vitest-environment jsdom
import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { beforeEach, afterEach, it, expect, vi } from "vitest";
import { PrefsProvider } from "../providers/PrefsContext";
import { usePrefs } from "../providers/prefs";
vi.mock("../lib", () => ({ getTransport: () => ({ invoke: async () => "linux/arm64" }) }));
let host: HTMLDivElement; let root: Root; let dark = false;
let listener: (() => void) | undefined;
const remove = vi.fn();
function Fixture() { const prefs = usePrefs(); return <><output>{prefs.theme}</output><button onClick={() => prefs.setTheme("system")}>System</button><button onClick={() => prefs.setTheme("dark")}>Dark</button><button onClick={() => prefs.setTheme("light")}>Light</button></>; }
beforeEach(() => {
  vi.stubGlobal("IS_REACT_ACT_ENVIRONMENT", true); localStorage.clear(); dark = false; listener = undefined; remove.mockReset();
  vi.stubGlobal("matchMedia", vi.fn(() => ({ get matches() { return dark; }, addEventListener: (_: string, fn: () => void) => { listener = fn; }, removeEventListener: remove })));
  host = document.createElement("div"); document.body.append(host); root = createRoot(host);
});
afterEach(async () => { await act(async () => root.unmount()); host.remove(); vi.unstubAllGlobals(); });
async function mount() { await act(async () => root.render(<PrefsProvider><Fixture /></PrefsProvider>)); }
async function choose(name: string) { await act(async () => [...host.querySelectorAll("button")].find(button => button.textContent === name)!.click()); }
it("defaults to System and follows OS appearance changes", async () => {
  await mount(); expect(host.querySelector("output")?.textContent).toBe("system"); expect(document.documentElement.dataset.theme).toBe("light");
  await act(async () => { dark = true; listener?.(); }); expect(document.documentElement.dataset.theme).toBe("dark");
});
it("preserves explicit choices and follows the OS again when System is restored", async () => {
  localStorage.setItem("hf_theme", "dark"); await mount(); expect(document.documentElement.dataset.theme).toBe("dark");
  await choose("System"); expect(localStorage.getItem("hf_theme")).toBe("system"); expect(document.documentElement.dataset.theme).toBe("light");
  await choose("Dark"); await act(async () => { dark = false; listener?.(); }); expect(document.documentElement.dataset.theme).toBe("dark");
});
it("loads a saved System preference and removes its listener on unmount", async () => {
  localStorage.setItem("hf_theme", "system"); await mount(); expect(document.documentElement.dataset.theme).toBe("light");
  await act(async () => root.render(null)); expect(remove).toHaveBeenCalled();
});
