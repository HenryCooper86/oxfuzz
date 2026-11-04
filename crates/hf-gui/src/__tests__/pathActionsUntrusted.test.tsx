// @vitest-environment jsdom
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { act } from "react";
import { createRoot } from "react-dom/client";
import { expect, it, vi } from "vitest";
import { PathActions } from "../components/PathActions";
import { I18nProvider } from "../i18n";

vi.mock("../lib", () => ({ getTransport: () => ({ invoke: vi.fn() }), isTauriEnvironment: () => true }));
vi.mock("../components/ui/toastContext", () => ({ useToast: () => ({ toast: vi.fn() }) }));

// Crash reproducers and corpus inputs are untrusted fuzz output. Handing them to
// the OS default application would process them on the host outside the sandbox.
it("offers copy and reveal but never opens a fuzz artifact with the default app", async () => {
  vi.stubGlobal("IS_REACT_ACT_ENVIRONMENT", true);
  const host = document.createElement("div"); document.body.append(host); const root = createRoot(host);
  try {
    await act(async () => root.render(<I18nProvider><PathActions path="/ws/crashes/crash-1" /></I18nProvider>));
    const labels = [...host.querySelectorAll("button")].map(button => button.getAttribute("aria-label"));
    expect(labels).toEqual(["Copy path", "Reveal in file manager"]);
  } finally { await act(async () => root.unmount()); host.remove(); vi.unstubAllGlobals(); }
});

it("does not register a desktop command that opens a path with the default app", () => {
  const shell = readFileSync(resolve(__dirname, "../../src-tauri/src/lib.rs"), "utf8");
  expect(shell).not.toMatch(/\bopen_path\b/);
});
