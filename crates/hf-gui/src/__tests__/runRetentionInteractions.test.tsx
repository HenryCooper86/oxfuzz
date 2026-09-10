// @vitest-environment jsdom
import { act } from "react";
import { createRoot } from "react-dom/client";
import { afterEach,expect,it,vi } from "vitest";
import { RunsView } from "../views/RunsView";
import { I18nProvider } from "../i18n";
import { ProjectProvider } from "../providers/ProjectContext";
import { ConfirmContext } from "../providers/confirm";
import { ToastProvider } from "../components/ui/Toast";
import { createHttpTransport } from "../lib/httpTransport";
import { createTauriTransport } from "../lib/tauriTransport";
import type { Transport } from "../lib/transport";
const mocks=vi.hoisted(()=>({transport:null as Transport|null,invoke:vi.fn()}));
vi.mock("../lib",async()=>({...await vi.importActual("../lib"),getTransport:()=>mocks.transport}));

const error={code:"run_retained_by_experiment",error:"run_retained_by_experiment",run_id:"10000000-0000-4000-8000-000000000001",experiment_id:"20000000-0000-4000-8000-000000000001",role:"baseline"};
const history=[{id:error.run_id,target_id:null,requested_duration_secs:null,project_root:"/project",target:"parse",kind:"Campaign",status:"Failed",engine:"libfuzzer",started_at:"2026-09-08T01:00:00Z",ended_at:"2026-09-08T02:00:00Z",duration_secs:60,crashes:0,edges:null,execs:null,harness_rev:null,binary_rev:null,evidence_dir:null}];
let cleanup=async()=>{};
afterEach(async()=>{await cleanup();vi.unstubAllGlobals();vi.restoreAllMocks();});
it.each(["http","native"])("actual RunsView shows deletion and clear retention on %s",async(transport)=>{
 vi.stubGlobal("IS_REACT_ACT_ENVIRONMENT",true);localStorage.clear();localStorage.setItem("hf_locale","en");localStorage.setItem("hf_active_project","/project");localStorage.setItem("hf_recent_projects",JSON.stringify(["/project"]));
 const host=document.createElement("div");document.body.append(host);const root=createRoot(host);cleanup=async()=>{await act(async()=>root.unmount());host.remove();};
 mocks.invoke.mockImplementation((command:string)=>command==="run_history"?Promise.resolve(history):command==="delete_run"||command==="clear_all_runs"?Promise.reject(error):Promise.resolve(null));
 vi.stubGlobal("fetch",vi.fn((url)=>{const path=new URL(String(url)).pathname;return Promise.resolve(new Response(JSON.stringify(path==="/runs/history"?history:path==="/runs/delete"||path==="/runs/clear"?error:null),{status:path==="/runs/delete"||path==="/runs/clear"?409:200}));}));
 vi.stubGlobal("__TAURI_INTERNALS__",{invoke:mocks.invoke});
 mocks.transport=transport==="http"?createHttpTransport():createTauriTransport();
 await act(async()=>root.render(<I18nProvider><ProjectProvider><ConfirmContext.Provider value={async()=>true}><ToastProvider><RunsView/></ToastProvider></ConfirmContext.Provider></ProjectProvider></I18nProvider>));await act(async()=>{await new Promise(r=>setTimeout(r,50));});
 for(let i=0;i<20&&!host.querySelector('[aria-label="Delete run"]');i++)await act(async()=>{await new Promise(r=>setTimeout(r,20));});
 const remove=host.querySelector<HTMLButtonElement>('[aria-label="Delete run"]')!;expect(remove,host.textContent+JSON.stringify(mocks.invoke.mock.calls)).toBeTruthy();await act(async()=>remove.click());expect(document.body.textContent).toContain(`Run ${error.run_id} is retained by experiment ${error.experiment_id} (baseline).`);
 const clear=[...host.querySelectorAll("button")].find(b=>b.textContent?.includes("Clear all"))!;expect(clear).toBeTruthy();await act(async()=>clear.click());expect(document.body.textContent).not.toContain("[object Object]");expect(host.textContent).toContain("parse");
});

it("focuses the requested retained run and explains a missing history entry", async () => {
 vi.stubGlobal("IS_REACT_ACT_ENVIRONMENT", true); localStorage.clear();
 localStorage.setItem("hf_active_project", "/project"); localStorage.setItem("hf_recent_projects", JSON.stringify(["/project"]));
 mocks.invoke.mockImplementation(async (command: string) => command === "run_history" ? [...history, {...history[0], id: "10000000-0000-4000-8000-000000000002", target: "other"}] : null);
 mocks.transport = { invoke: mocks.invoke, listen: async () => () => {} };
 const host = document.createElement("div"); document.body.append(host); const root = createRoot(host);
 cleanup = async () => { await act(async () => root.unmount()); host.remove(); };
 const clear = vi.fn();
 const render = (id: string) => root.render(<I18nProvider><ProjectProvider><RunsView focus={{project: "/project", id}} onClearFocus={clear}/></ProjectProvider></I18nProvider>);
 await act(async () => render(error.run_id));
 expect(host.querySelectorAll('[aria-label="Delete run"]')).toHaveLength(1);
 expect(host.textContent).toContain(`Reviewing retained run ${error.run_id}`);
 await act(async () => [...host.querySelectorAll("button")].find(b => b.textContent === "Show all runs")!.click());
 expect(clear).toHaveBeenCalledOnce();
 await act(async () => render("10000000-0000-4000-8000-000000000003"));
 expect(host.textContent).toContain("This run is not present in retained history");
 expect(host.querySelectorAll('[aria-label="Delete run"]')).toHaveLength(0);
});
