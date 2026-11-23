// @vitest-environment jsdom
import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { I18nProvider } from "../i18n";
import { ReportPreview } from "../components/ReportPreview";

vi.mock("../components/Mermaid", () => ({ Mermaid: () => null }));

let host: HTMLDivElement; let root: Root;
beforeEach(() => { vi.stubGlobal("IS_REACT_ACT_ENVIRONMENT", true); host = document.createElement("div"); document.body.append(host); root = createRoot(host); });
afterEach(async () => { await act(async () => root.unmount()); host.remove(); vi.unstubAllGlobals(); });

it("closes the report preview on Escape", async () => {
  const onClose = vi.fn();
  await act(async () => root.render(<I18nProvider><ReportPreview markdown="# Report" onClose={onClose} onExport={() => {}} formats={["md"]} /></I18nProvider>));
  expect(host.querySelector('[role="dialog"]')).not.toBeNull();
  await act(async () => { document.dispatchEvent(new KeyboardEvent("keydown", { key: "Escape", bubbles: true })); });
  expect(onClose).toHaveBeenCalledTimes(1);
});
