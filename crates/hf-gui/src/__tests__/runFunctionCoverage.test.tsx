// @vitest-environment jsdom
import { act } from "react";
import { createRoot } from "react-dom/client";
import { expect, it, vi } from "vitest";
import { I18nProvider } from "../i18n";
import { RunFunctionCoverage } from "../components/RunFunctionCoverage";
const mock = vi.hoisted(() => ({ invoke: vi.fn() }));
vi.mock("../lib", () => ({ getTransport: () => ({ invoke: mock.invoke }) }));

it("reads exact run evidence only on request and preserves 64-bit counters", async () => {
  vi.stubGlobal("IS_REACT_ACT_ENVIRONMENT", true);
  mock.invoke.mockResolvedValue({ status: "available", run_id: "run-a", binary_sha256: "binary", export_sha256: "export", observed_functions: 1,
    functions: [{ name: "parse", count: "18446744073709551615", files: ["/work/parser.c"] }], limitation: "Profiles can be incomplete." });
  const host = document.createElement("div"); document.body.append(host); const root = createRoot(host);
  try {
    await act(async () => root.render(<I18nProvider><RunFunctionCoverage runId="run-a" /></I18nProvider>));
    expect(mock.invoke).not.toHaveBeenCalled();
    await act(async () => host.querySelector("button")!.click());
    expect(mock.invoke).toHaveBeenCalledExactlyOnceWith("run_function_coverage", { runId: "run-a" });
    expect(host.textContent).toContain("18446744073709551615");
    expect(host.textContent).toContain("/work/parser.c");
  } finally { await act(async () => root.unmount()); host.remove(); vi.unstubAllGlobals(); }
});
