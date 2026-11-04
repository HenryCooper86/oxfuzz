// @vitest-environment jsdom
import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, expect, it, vi } from "vitest";
import { HarnessReadyCard, RunCompletionActions } from "../components/StageHandoff";
import { I18nProvider } from "../i18n";

let host: HTMLDivElement; let root: Root;
async function render(node: React.ReactNode) {
  vi.stubGlobal("IS_REACT_ACT_ENVIRONMENT", true);
  host = document.createElement("div"); document.body.append(host); root = createRoot(host);
  await act(async () => root.render(<I18nProvider>{node}</I18nProvider>));
}
afterEach(async () => { await act(async () => root.unmount()); host.remove(); vi.unstubAllGlobals(); });
const buttons = () => [...host.querySelectorAll("button")];

it("continues from a ready harness to the Run stage", async () => {
  const navigate = vi.fn();
  await render(<HarnessReadyCard target="parse" engine="libfuzzer" onNavigate={navigate} />);
  expect(host.textContent).toContain("Harness ready to fuzz");
  const next = buttons().find(button => button.textContent === "Continue to Run");
  expect(next).toBeTruthy();
  await act(async () => next!.click());
  expect(navigate).toHaveBeenCalledWith("run");
});

it("offers findings review first when a finished run retained crashes", async () => {
  const navigate = vi.fn();
  await render(<RunCompletionActions crashes={3} onNavigate={navigate} />);
  expect(buttons().map(button => button.textContent)).toEqual(["Review findings", "Run History"]);
  await act(async () => buttons()[0].click());
  expect(navigate).toHaveBeenCalledWith("triage");
});

it("offers only run history when a finished run retained no crashes", async () => {
  const navigate = vi.fn();
  await render(<RunCompletionActions crashes={0} onNavigate={navigate} />);
  expect(buttons().map(button => button.textContent)).toEqual(["Run History"]);
  await act(async () => buttons()[0].click());
  expect(navigate).toHaveBeenCalledWith("runs");
});
