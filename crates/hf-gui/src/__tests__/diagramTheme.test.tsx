// @vitest-environment jsdom
import { act } from "react";
import { createRoot } from "react-dom/client";
import { expect, it, vi } from "vitest";
import { Mermaid } from "../components/Mermaid";
const fixture = vi.hoisted(() => ({ theme: "light", initialize: vi.fn(), render: vi.fn(async () => ({ svg: "<svg></svg>" })) }));
vi.mock("mermaid", () => ({ default: { initialize: fixture.initialize, render: fixture.render } }));
vi.mock("../providers/prefs", () => ({ usePrefs: () => ({ resolvedTheme: fixture.theme }) }));
it("renders diagrams in the resolved appearance and rerenders after it changes", async () => {
  vi.stubGlobal("IS_REACT_ACT_ENVIRONMENT", true);
  const host = document.createElement("div"); const root = createRoot(host);
  try {
    await act(async () => root.render(<Mermaid code="graph TD; A-->B" />));
    expect(fixture.initialize).toHaveBeenLastCalledWith(expect.objectContaining({ theme: "default", securityLevel: "strict" }));
    fixture.theme = "dark"; await act(async () => root.render(<Mermaid code="graph TD; A-->B" />));
    expect(fixture.initialize).toHaveBeenLastCalledWith(expect.objectContaining({ theme: "dark", securityLevel: "strict" }));
    expect(fixture.render).toHaveBeenCalledTimes(2);
  } finally { await act(async () => root.unmount()); vi.unstubAllGlobals(); }
});
