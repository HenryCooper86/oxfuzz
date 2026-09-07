// @vitest-environment jsdom
import { act } from "react";
import { createRoot } from "react-dom/client";
import { afterEach, expect, it, vi } from "vitest";
import App from "../App";
import type { ViewType } from "../types";
const invoke=vi.hoisted(()=>vi.fn());
vi.mock("../lib",async()=>({...await vi.importActual("../lib"),getTransport:()=>({invoke,listen:async()=>()=>{}})}));
vi.mock("../components/Sidebar",()=>({Sidebar:({onNavigate}:{onNavigate:(view:ViewType)=>void})=><><button onClick={()=>onNavigate("corpus")}>Sidebar Corpus</button><button onClick={()=>onNavigate("workflow")}>Sidebar Workflow</button></>}));
vi.mock("../components/Header",()=>({Header:()=>null}));vi.mock("../components/StatusBar",()=>({StatusBar:()=>null}));vi.mock("../components/RecoveryBanner",()=>({RecoveryBanner:()=>null}));vi.mock("../components/CommandPalette",()=>({CommandPalette:()=>null}));vi.mock("../components/ProgressPanel",()=>({ProgressPanel:()=>null}));
vi.mock("../views/DashboardView",()=>({DashboardView:()=> <p>Dashboard</p>}));
vi.mock("../views/DiscoverView",()=>({DiscoverView:()=> <p>Discover stage</p>}));
vi.mock("../views/HarnessView",()=>({HarnessView:()=> <p>Existing Harness controls</p>}));
vi.mock("../views/RunView",()=>({RunView:()=> <p>Existing Run controls</p>}));
vi.mock("../views/TriageView",()=>({TriageView:()=> <p>Triage stage</p>}));
let cleanup=async()=>{};afterEach(async()=>{await cleanup();vi.unstubAllGlobals();vi.restoreAllMocks();});
it.each(["Sidebar Corpus","Sidebar Workflow"])("loads real Corpus and explicitly navigates from %s",async(entry)=>{
 vi.stubGlobal("IS_REACT_ACT_ENVIRONMENT",true);HTMLElement.prototype.scrollIntoView=vi.fn();localStorage.clear();localStorage.setItem("hf_locale","en");localStorage.setItem("hf_setup_completed","true");localStorage.setItem("hf_active_project","/project");localStorage.setItem("hf_recent_projects",JSON.stringify(["/project"]));localStorage.setItem("hf_target_selection_v1",JSON.stringify({"/project":{target:"parse",engine:"libfuzzer",lang:"c",compiled:false}}));
 const run={id:"10000000-0000-4000-8000-000000000001",target_id:"20000000-0000-4000-8000-000000000001",target:"parse",project_root:"/project",kind:"Campaign",status:"Done",ended_at:"2026-09-08T02:00:00Z",started_at:"2026-09-08T01:00:00Z",requested_duration_secs:60};
 const saved={id:"30000000-0000-4000-8000-000000000001",status:"prepared",kind:"refine_harness",goal_function:"parse",hypothesis:"reviewed operator intent",baseline:{run_id:run.id,status:"done",duration_secs:60,seed:null,max_mem_mb:"1024",edges:null,build_inputs:null}};
 invoke.mockReset();invoke.mockImplementation(async(command,args)=>{if(command==="run_history")return[run];if(command==="coverage_experiment_list")return{items:[saved],next_cursor:null};if(command==="coverage_experiment_get")return saved;if(command==="corpus_capabilities")return{};if(command==="run_owner")return{run_id:args.runId,project_root:"/project",target:"parse",engine:"libfuzzer",kind:"Campaign",status:"Done",started_at:run.started_at};if(command==="campaign_health_events")return{events:[],next_cursor:null};return[];});
 const host=document.createElement("div");document.body.append(host);const root=createRoot(host);cleanup=async()=>{await act(async()=>root.unmount());host.remove();};await act(async()=>root.render(<App/>));
 const click=async(text:string)=>{const button=[...host.querySelectorAll("button")].find(b=>b.textContent?.includes(text)&&(text!=="Corpus"||!b.textContent.includes("Sidebar")));expect(button,text).toBeTruthy();await act(async()=>button!.click());await act(async()=>{await new Promise(r=>setTimeout(r,30));});};
 await click(entry);if(entry==="Sidebar Workflow")await click("Corpus");
 for(let i=0;i<10&&!host.querySelector('[aria-label="Experiment history"]');i++)await act(async()=>{await new Promise(r=>setTimeout(r,20));});
 expect(host.textContent).toContain("Coverage experiments");const history=host.querySelector<HTMLSelectElement>('[aria-label="Experiment history"]')!;await act(async()=>{history.value=saved.id;history.dispatchEvent(new Event("change",{bubbles:true}));});await click("Open Harness");expect(host.textContent).toContain("Existing Harness controls");expect(invoke.mock.calls.some(([cmd])=>/compile|refine|seed|promote|run_fuzzer/.test(cmd))).toBe(false);
 if(entry==="Sidebar Workflow"){expect(host.textContent).toContain("Fuzzing Workflow");await click("Corpus");}else await click("Sidebar Corpus");
 const reopened=host.querySelector<HTMLSelectElement>('[aria-label="Experiment history"]')!;expect(reopened).toBeTruthy();expect(reopened.value).toBe(saved.id);await click("Open Run");expect(host.textContent).toContain("Existing Run controls");
});
