// @vitest-environment jsdom
import { act } from "react";
import { createRoot } from "react-dom/client";
import { expect, it, vi } from "vitest";
import { I18nProvider } from "../i18n";
import { RunEvidenceSummary } from "../components/RunEvidenceSummary";
import type { RunHistoryItem } from "../types";
it("explains the observed scope without treating zero crashes or missing coverage as safety", async () => {
  vi.stubGlobal("IS_REACT_ACT_ENVIRONMENT", true);
  const run: RunHistoryItem = {id:"run-one", project_root:"/project",target:"parse",target_selector:"parser.c::parse",target_id:"target-one",engine:"libfuzzer",status:"Done",kind:"Campaign",crashes:0,edges:null,execs:null,requested_duration_secs:60,duration_secs:8,started_at:"2026-09-10T00:00:00Z",ended_at:"2026-09-10T00:00:08Z",harness_rev:null,binary_rev:null,evidence_dir:null,comparison_key:null};
  const findings=vi.fn(), report=vi.fn(); const host=document.createElement("div"); const root=createRoot(host);
  try {
    await act(async()=>root.render(<I18nProvider><RunEvidenceSummary run={run} onFindings={findings} onReport={report}/></I18nProvider>));
    expect(host.textContent).toContain("parser.c::parse");
    expect(host.textContent).toContain("No crash artifacts were retained");
    expect(host.textContent).toContain("does not establish that the project is safe");
    expect(host.textContent).toContain("Coverage was not recorded");
    await act(async()=>[...host.querySelectorAll("button")].find(b=>b.textContent==="Review findings")!.click());
    expect(findings).toHaveBeenCalledOnce(); expect(report).not.toHaveBeenCalled();
    await act(async()=>root.render(<I18nProvider><RunEvidenceSummary run={{...run,status:"Cancelled",crashes:2,edges:42}} onFindings={findings}/></I18nProvider>));
    expect(host.textContent).toContain("Cancelled"); expect(host.textContent).toContain("2 retained crash artifacts");
    expect(host.textContent).not.toContain("No crash artifacts were retained");
  } finally { await act(async()=>root.unmount());vi.unstubAllGlobals(); }
});
