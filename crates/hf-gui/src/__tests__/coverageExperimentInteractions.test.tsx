// @vitest-environment jsdom
import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach,beforeEach,expect,it,vi } from "vitest";
import { CorpusView } from "../views/CorpusView";
import { I18nProvider } from "../i18n";
import { ProjectProvider } from "../providers/ProjectContext";
import { TargetProvider } from "../providers/TargetContext";
import { useProject } from "../providers/project";
import { useTarget } from "../providers/target";
import { createTauriTransport } from "../lib/tauriTransport";
import { createHttpTransport } from "../lib/httpTransport";
const state=vi.hoisted(()=>({transport:null as ReturnType<typeof createHttpTransport>|null}));
vi.mock("../lib",async()=>({...await vi.importActual("../lib"),getTransport:()=>state.transport}));
let host:HTMLDivElement,root:Root,records:Record<string,unknown>[],calls:string[],rejectAttach:boolean;
const baseline="10000000-0000-4000-8000-000000000001",later="10000000-0000-4000-8000-000000000002",targetId="20000000-0000-4000-8000-000000000001",experimentId="30000000-0000-4000-8000-000000000001";
const navigate=vi.fn();
const run=(id:string)=>({id,project_root:"/project-a",target:"parse",target_id:targetId,requested_duration_secs:60,kind:"Campaign",status:id===later?"Failed":"Done",started_at:id===later?"2026-09-08T04:00:00.000000000Z":"2026-09-08T01:00:00.000000000Z",ended_at:"2026-09-08T05:00:00.000000000Z",duration_secs:2});
const evidence=(id:string)=>({run_id:id,status:id===later?"failed":"done",duration_secs:60,seed:"18446744073709551615",max_mem_mb:"9223372036854775807",edges:"9007199254740993",build_inputs:null});
function Controls(){const {setActiveProject}=useProject();const {setTarget}=useTarget();return <><button onClick={()=>setActiveProject("/project-b")}>Switch project</button><button onClick={()=>setTarget("other")}>Switch target</button><CorpusView onNavigate={navigate}/></>;}
async function flush(){await act(async()=>{await new Promise(r=>setTimeout(r,10));});}
async function mount(){await act(async()=>root.render(<I18nProvider><ProjectProvider><TargetProvider><Controls/></TargetProvider></ProjectProvider></I18nProvider>));await flush();}
function button(label:string){const el=[...host.querySelectorAll("button")].find(b=>b.textContent===label);expect(el,label).toBeTruthy();return el!;}
async function click(label:string){await act(async()=>button(label).click());await flush();}
async function field(label:string,value:string){const el=host.querySelector<HTMLInputElement|HTMLSelectElement|HTMLTextAreaElement>(`[aria-label="${label}"]`)!;expect(el,label).toBeTruthy();await act(async()=>{Object.getOwnPropertyDescriptor(Object.getPrototypeOf(el),"value")!.set!.call(el,value);el.dispatchEvent(new Event(el.tagName==="SELECT"?"change":"input",{bubbles:true}));});}
const json=(value:unknown,status=200)=>new Response(JSON.stringify(value),{status,headers:{"content-type":"application/json"}});
function fetchRequest(input:RequestInfo|URL,init?:RequestInit):Promise<Response>{const url=new URL(String(input));calls.push(`${init?.method} ${url.pathname}`);const body=init?.body?JSON.parse(String(init.body)):{};
 if(url.pathname==="/runs/history")return Promise.resolve(json(body.project==="/project-a"?[run(baseline),run(later)]:[]));
 if(url.pathname==="/corpus/list")return Promise.resolve(json([]));
 if(url.pathname==="/corpus/capabilities")return Promise.resolve(json({}));
 if(url.pathname==="/coverage/blockers")return Promise.resolve(json({code:"feature_unavailable",error:"not included"},501));
 if(url.pathname==="/coverage/experiments"&&init?.method==="GET")return Promise.resolve(json({schema_version:1,items:records,next_cursor:null}));
 if(url.pathname==="/coverage/experiments"&&init?.method==="POST"){const record={...body,id:experimentId,project_root:body.project,target_symbol:"parse",baseline:evidence(body.baseline_run_id),status:"prepared",created_at:"2026-09-08T03:00:00.000000000Z",result:null,cancellation_reason:null};records=[record];return Promise.resolve(json(record));}
 if(url.pathname.endsWith("/complete")){if(rejectAttach)return Promise.resolve(json({code:"different_build_inputs",error:"different_build_inputs"},422));records[0]={...records[0],status:"completed",result:{run:evidence(body.result_run_id),input_change:"no_observed_input_change",build_comparison:"unavailable_legacy",edge_comparison:{status:"unavailable",reason_code:"legacy_build_inputs_unavailable"},target_entry:{status:"unavailable",reason_code:"no_exact_run_scoped_function_coverage"},limitations:["aggregate_edges_not_function_entry","result_failed","random_seed_unrecorded"]}};return Promise.resolve(json(records[0]));}
 if(url.pathname.endsWith("/cancel")){records[0]={...records[0],status:"cancelled",cancellation_reason:body.reason};return Promise.resolve(json(records[0]));}
 if(url.pathname===`/coverage/experiments/${experimentId}`)return Promise.resolve(json(records[0]));
 return Promise.resolve(json({error:`Unexpected ${url.pathname}`},404));}
beforeEach(()=>{vi.stubGlobal("IS_REACT_ACT_ENVIRONMENT",true);localStorage.clear();localStorage.setItem("hf_locale","en");localStorage.setItem("hf_recent_projects",JSON.stringify(["/project-a","/project-b"]));localStorage.setItem("hf_active_project","/project-a");localStorage.setItem("hf_target_selection_v1",JSON.stringify({"/project-a":{target:"parse",engine:"libfuzzer",lang:"c",compiled:false},"/project-b":{target:"parse",engine:"libfuzzer",lang:"c",compiled:false}}));host=document.createElement("div");document.body.append(host);root=createRoot(host);records=[];calls=[];rejectAttach=false;navigate.mockReset();state.transport=createHttpTransport();vi.stubGlobal("fetch",vi.fn(fetchRequest));});
afterEach(async()=>{await act(async()=>root.unmount());host.remove();vi.unstubAllGlobals();});
async function prepare(){await field("Baseline campaign",baseline);await field("Goal function","parse_deep");await field("Operator hypothesis","More inputs may reach the goal");await click("Prepare experiment");}
it("persists before explicit navigation, reopens, retains a refused attachment, then attaches the exact failed later campaign",async()=>{await mount();await prepare();expect(records[0].baseline_run_id).toBe(baseline);expect(records[0].target_id).toBe(targetId);expect(records[0].duration_secs).toBe(60);expect(navigate).not.toHaveBeenCalled();await click("Open Corpus");expect(navigate).toHaveBeenCalledWith("corpus");await click("Open Run");expect(navigate).toHaveBeenLastCalledWith("run");await click("New experiment");await field("Experiment history",experimentId);expect(host.textContent).toContain("More inputs may reach the goal");rejectAttach=true;await field("Result campaign",later);await click("Attach result");expect(host.textContent).toContain("Build inputs differ");expect(records[0].status).toBe("prepared");rejectAttach=false;await click("Attach result");expect(host.textContent).toContain("Result campaign failed");expect(host.textContent).toContain("No observed input change");expect(host.textContent).toContain("Exact run-scoped function coverage is unavailable");expect(host.textContent).toContain("18446744073709551615");expect(calls.some(c=>/start|refine|promot|seed|discover|grow/.test(c))).toBe(false);});
it("cancels explicitly and displays retained reason",async()=>{await mount();await prepare();await field("Cancellation reason","Different approach needed");await click("Cancel experiment");expect(host.textContent).toContain("Different approach needed");expect(records[0].status).toBe("cancelled");});
it.each(["Switch project","Switch target"])("isolates late create success after %s",async(label)=>{let release:(value:Response)=>void=()=>{};vi.stubGlobal("fetch",vi.fn((url,init)=>init?.method==="POST"&&new URL(String(url)).pathname==="/coverage/experiments"?new Promise<Response>(r=>{release=r;}):fetchRequest(url,init)));await mount();await field("Baseline campaign",baseline);await field("Goal function","old goal");await field("Operator hypothesis","old hypothesis");await click("Prepare experiment");await click(label);await act(async()=>release(json({id:experimentId,status:"prepared",goal_function:"old goal",baseline:evidence(baseline)})));await flush();expect(host.textContent).not.toContain("old goal");expect(navigate).not.toHaveBeenCalled();});
it.each([501,403,404,500])("renders HTTP %s accurately",async(status)=>{vi.stubGlobal("fetch",vi.fn((url,init)=>new URL(String(url)).pathname==="/coverage/experiments"?Promise.resolve(json({code:status===501?"feature_unavailable":status===403?"project_not_authorized":status===404?"not_found":"storage_error",error:"failure"},status)):fetchRequest(url,init)));await mount();expect(host.textContent).toContain(status===501?"Coverage experiments are not included in this application build":status===403?"Project is not authorized":status===404?"Experiment was not found":"Experiment storage failed");if(status===501)expect(button("Prepare experiment").disabled).toBe(true);});
it("prefills reviewed advice without exploration for manual history",async()=>{
 await mount();expect(calls.some(c=>c.includes("blockers"))).toBe(false);
 vi.stubGlobal("fetch",vi.fn((url,init)=>new URL(String(url)).pathname==="/coverage/blockers"?Promise.resolve(json({measurement:{status:"available"},experiment:{kind:"refine_harness",target_function:"advised_function",reason_code:"frontier_blocked"},blockers:[]})):fetchRequest(url,init)));
 await click("Explore blockers");await click("Use this advice");expect((host.querySelector('[aria-label="Goal function"]') as HTMLInputElement).value).toBe("advised_function");expect((host.querySelector('[aria-label="Intervention"]') as HTMLSelectElement).value).toBe("refine_harness");expect(records).toHaveLength(0);
});
it.each(["get","complete","cancel"])("isolates delayed %s response after switching targets",async(operation)=>{
 await mount();await prepare();let release:(value:Response)=>void=()=>{};
 vi.stubGlobal("fetch",vi.fn((url,init)=>new URL(String(url)).pathname===`/coverage/experiments/${experimentId}${operation==="get"?"":`/${operation}`}`?new Promise<Response>(r=>{release=r;}):fetchRequest(url,init)));
 if(operation==="get"){await click("New experiment");await field("Experiment history",experimentId);}
 if(operation==="complete"){await field("Result campaign",later);await click("Attach result");}
 if(operation==="cancel"){await field("Cancellation reason","old cancellation");await click("Cancel experiment");}
 await click("Switch target");await act(async()=>release(json({code:"feature_unavailable",error:"coverage experiments are not included in this application build"},501)));await flush();expect(host.textContent).not.toContain("Coverage experiments are not included");expect(host.textContent).not.toContain("old cancellation");expect(host.textContent).not.toContain(experimentId);
});
it("ignores late history absence after project switch",async()=>{
 let release:(value:Response)=>void=()=>{};
 vi.stubGlobal("fetch",vi.fn((url,init)=>new URL(String(url)).pathname==="/coverage/experiments"?new Promise<Response>(r=>{release=r;}):fetchRequest(url,init)));
 await mount();await click("Switch project");await act(async()=>release(json({code:"feature_unavailable",error:"unavailable"},501)));await flush();expect(host.textContent).not.toContain("Coverage experiments are not included");
});
it("recovers an uncertain create from history without resubmitting",async()=>{
 await mount();const fetch=vi.fn((url,init)=>{const response=fetchRequest(url,init);return new URL(String(url)).pathname==="/coverage/experiments"&&init?.method==="POST"?Promise.reject(new TypeError("connection lost")):response;});vi.stubGlobal("fetch",fetch);await prepare();expect(host.textContent).toContain("The preparation response is uncertain");expect(button("Prepare experiment").disabled).toBe(true);await click("Refresh experiment history");await field("Experiment history",experimentId);expect(host.textContent).toContain("More inputs may reach the goal");expect(fetch.mock.calls.filter(([url,init])=>new URL(String(url)).pathname==="/coverage/experiments"&&init?.method==="POST")).toHaveLength(1);
});

it.each(["initial", "pending create"])("keeps uncertain preparation locked after a stale %s history response", async (timing) => {
 let releaseHistory: (response: Response) => void = () => {};
 let loseCreate: (error: Error) => void = () => {};
 let deferHistory = timing === "initial";
 const fetch = vi.fn((url: RequestInfo | URL, init?: RequestInit) => {
  if (new URL(String(url)).pathname === "/coverage/experiments") {
   if (init?.method === "GET" && deferHistory) return new Promise<Response>(resolve => { releaseHistory = resolve; });
   if (init?.method === "POST") {
    void fetchRequest(url, init);
    return new Promise<Response>((_resolve, reject) => { loseCreate = reject; });
   }
  }
  return fetchRequest(url, init);
 });
 vi.stubGlobal("fetch", fetch);
 await mount();
 await prepare();
 expect(records).toHaveLength(1);
 if (timing === "pending create") { deferHistory = true; await click("Refresh experiment history"); }
 await act(async () => loseCreate(new TypeError("connection lost")));
 await flush();
 expect(host.textContent).toContain("The preparation response is uncertain");
 expect(button("Prepare experiment").disabled).toBe(true);
 await act(async () => releaseHistory(json({ schema_version: 1, items: [], next_cursor: null })));
 await flush();
 expect(host.textContent).toContain("The preparation response is uncertain");
 expect(button("Prepare experiment").disabled).toBe(true);
 await click("Prepare experiment");
 expect(fetch.mock.calls.filter(([url, init]) => new URL(String(url)).pathname === "/coverage/experiments" && init?.method === "POST")).toHaveLength(1);
 await click("Refresh experiment history");
 expect(button("Prepare experiment").disabled).toBe(true);
 await act(async () => releaseHistory(json({ schema_version: 1, items: records, next_cursor: null })));
 await flush();
 expect(host.textContent).not.toContain("The preparation response is uncertain");
 expect(button("Prepare experiment").disabled).toBe(false);
 await field("Experiment history", experimentId);
 expect(host.textContent).toContain("More inputs may reach the goal");
 expect(navigate).not.toHaveBeenCalled();
 expect(fetch.mock.calls.filter(([url, init]) => new URL(String(url)).pathname === "/coverage/experiments" && init?.method === "POST")).toHaveLength(1);
});

it("renders paired native unavailable without hiding ordinary storage errors",async()=>{
 const nativeInvoke=vi.fn(async(command:string,args:unknown)=>{
  if(command.startsWith("coverage_experiment_")){expect(Object.prototype.toString.call(args)).toBe("[object Uint8Array]");throw {code:"feature_unavailable",error:"coverage experiments are not included in this application build"};}
  if(command==="run_history")return[run(baseline)];
  if(command==="corpus_list")return[];
  return{};
 });
 vi.stubGlobal("__TAURI_INTERNALS__",{invoke:nativeInvoke});state.transport=createTauriTransport();await mount();
 for(let i=0;i<20&&!host.textContent?.includes("Coverage experiments are not included");i++)await flush();
 expect(host.textContent).toContain("Coverage experiments are not included in this application build");expect(button("Prepare experiment").disabled).toBe(true);
});
it("requires explicit retained UUID selection for duplicate symbols",async()=>{
 const otherTarget="20000000-0000-4000-8000-000000000002";
 vi.stubGlobal("fetch",vi.fn((url,init)=>new URL(String(url)).pathname==="/runs/history"?Promise.resolve(json([run(baseline),{...run(later),target_id:otherTarget}])):fetchRequest(url,init)));
 await mount();expect(host.querySelector('[aria-label="Baseline campaign"]')).toBeNull();await field("Retained target ID",otherTarget);await flush();await field("Baseline campaign",later);await field("Goal function","parse");await field("Operator hypothesis","Retain failed baseline");await click("Prepare experiment");expect(records[0].target_id).toBe(otherTarget);expect(records[0].baseline_run_id).toBe(later);
});
it("renders Chinese preparation and terminal limitation labels",async()=>{
 localStorage.setItem("hf_locale","zh");await mount();await field("基线活动",baseline);await field("目标函数","parse");await field("操作员假设","测试输入可能到达目标");await click("准备实验");await field("结果活动",later);await click("关联结果");expect(host.textContent).toContain("结果活动失败");expect(host.textContent).toContain("精确的单次运行函数覆盖率不可用");expect(host.textContent).not.toContain("experiments.");
});
it("renders safe integer strings and independent observed edge facts without causal percentages",async()=>{
 await mount();await prepare();vi.stubGlobal("fetch",vi.fn((url,init)=>new URL(String(url)).pathname.endsWith("/complete")?Promise.resolve(json({...records[0],status:"completed",result:{run:evidence(later),input_change:"harness_source_changed",build_comparison:"matched",edge_comparison:{status:"observed",baseline_edges:"9007199254740993",result_edges:"9007199254740994",delta:"1"},target_entry:{status:"unavailable",reason_code:"no_exact_run_scoped_function_coverage"},limitations:["aggregate_edges_not_function_entry","result_failed","harness_instrumentation_may_differ"]}})):fetchRequest(url,init)));await field("Result campaign",later);await click("Attach result");expect(host.textContent).toContain("9007199254740993 → 9007199254740994 (1)");expect(host.textContent).toContain("Harness instrumentation may differ");expect(host.textContent).toContain("Result campaign failed");expect(host.textContent).not.toContain("%");
});
