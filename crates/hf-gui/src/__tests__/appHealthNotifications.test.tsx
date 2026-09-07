// @vitest-environment jsdom
import { StrictMode, act } from "react";
import { createRoot } from "react-dom/client";
import { afterEach, expect, it, vi } from "vitest";
import App from "../App";

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

const callbacks = new Map<string, Array<(event: { payload: unknown }) => void>>();
const invoke = vi.fn();
vi.mock("../lib", async () => ({
  ...(await vi.importActual<typeof import("../lib")>("../lib")),
  getTransport: () => ({
    invoke,
    listen: async (event: string, callback: (event: { payload: unknown }) => void) => {
      callbacks.set(event, [...(callbacks.get(event) ?? []), callback]);
      return () => {
        callbacks.set(
          event,
          (callbacks.get(event) ?? []).filter((entry) => entry !== callback),
        );
      };
    },
  }),
}));
// Leave App and every shared provider real; replace unrelated presentation surfaces.
vi.mock("../views/DashboardView", () => ({ DashboardView: () => <p>Dashboard</p> }));
vi.mock("../components/Sidebar", () => ({ Sidebar: () => null }));
vi.mock("../components/Header", () => ({ Header: () => null }));
vi.mock("../components/StatusBar", () => ({ StatusBar: () => null }));
vi.mock("../components/RecoveryBanner", () => ({ RecoveryBanner: () => null }));
vi.mock("../components/CommandPalette", () => ({ CommandPalette: () => null }));
vi.mock("../components/ProgressPanel", () => ({ ProgressPanel: () => null }));

const runId = "00000000-0000-4000-8000-000000000001";
const owner = {
  run_id: runId,
  project_root: "/project",
  target: "parse",
  engine: "libfuzzer",
  kind: "Campaign",
  status: "Done",
  started_at: "2026-09-07T00:00:00Z",
};
function health(id: number, severity: "warning" | "error" = "error") {
  return {
    schema_version: 2,
    id: `00000000-0000-4000-8000-${String(id).padStart(12, "0")}`,
    run_id: runId,
    condition: "run_failed",
    severity,
    detail: `Health detail ${id}`,
    observed_at: "2026-09-07T00:01:00Z",
    evidence: { schema_version: 2, run_id: runId, condition: "run_failed" },
  };
}
async function emit(event: string, payload: unknown) {
  await act(async () => {
    for (const callback of callbacks.get(event) ?? []) callback({ payload });
  });
}

afterEach(() => {
  localStorage.clear();
  callbacks.clear();
  vi.useRealTimers();
});

it("shows live health errors once through the actual App provider hierarchy while retained errors and warnings stay silent", async () => {
  vi.useFakeTimers();
  localStorage.setItem("hf_setup_completed", "true");
  localStorage.setItem("hf_active_project", "/project");
  localStorage.setItem("hf_recent_projects", JSON.stringify(["/project"]));
  invoke.mockImplementation(async (command: string) => {
    if (command === "run_history") return [{ id: runId }];
    if (command === "run_owner") return owner;
    if (command === "campaign_health_events") return { events: [health(100)], next_cursor: null };
    return [];
  });
  const container = document.createElement("div");
  document.body.append(container);
  const root = createRoot(container);
  try {
    await act(async () =>
      root.render(
        <StrictMode>
          <App />
        </StrictMode>,
      ),
    );
    expect(container.querySelectorAll('[role="region"][aria-live="assertive"]')).toHaveLength(1);
    expect(container.querySelectorAll('[role="region"] [role="alert"]')).toHaveLength(0);
    await emit("campaign:health", { owner, event: health(100) });
    await emit("campaign:health", { owner, event: health(101, "warning") });
    expect(container.querySelectorAll('[role="region"] [role="alert"]')).toHaveLength(0);
    await emit("campaign:health", { owner, event: health(102) });
    await emit("campaign:health", { owner, event: health(102) });
    expect(container.querySelectorAll('[role="region"] [role="alert"]')).toHaveLength(1);
    expect(container.querySelector('[role="region"] [role="alert"]')?.textContent).toContain(
      "Health detail 102",
    );
    await emit("campaign:crash", {
      target: "parse",
      crashes: 1,
      report_saved: false,
      defectdojo_pushed: false,
    });
    expect(container.querySelectorAll('[role="region"] [role="alert"]')).toHaveLength(2);
  } finally {
    await act(async () => root.unmount());
    container.remove();
  }
});
