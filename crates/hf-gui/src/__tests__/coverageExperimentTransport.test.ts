import { afterEach, describe, expect, it, vi } from "vitest";
import { createHttpTransport } from "../lib/httpTransport";
import { createTauriTransport } from "../lib/tauriTransport";
const invoke = vi.hoisted(() => vi.fn().mockResolvedValue({}));
vi.mock("@tauri-apps/api/core", () => ({ invoke, Channel: class {} }));
afterEach(() => { vi.unstubAllGlobals(); invoke.mockClear(); });
const scope = { project: "/project", target_id: "10000000-0000-4000-8000-000000000001" };
const id = "20000000-0000-4000-8000-000000000001";
describe("experiment transport", () => {
  it("preserves structured HTTP errors without conflating ordinary refusals with absence", async () => {
    for (const [status,code] of [[501,"feature_unavailable"],[403,"project_not_authorized"],[404,"not_found"],[500,"storage_error"],[409,"run_retained_by_experiment"]] as const) {
      const error = { code, error: code === "feature_unavailable" ? "coverage experiments are not included in this application build" : code, run_id:id, experiment_id:id, role:"baseline" };
      vi.stubGlobal("fetch",vi.fn().mockResolvedValue(new Response(JSON.stringify(error),{status})));
      await expect(createHttpTransport().invoke("coverage_experiment_list",{...scope,limit:20,before:null})).rejects.toMatchObject(error);
    }
  });
  it("maps all five operations and preserves exact cursor timestamps", async () => {
    const fetch = vi.fn().mockImplementation(() => Promise.resolve(new Response("{}")));
    vi.stubGlobal("fetch",fetch); const transport=createHttpTransport();
    await transport.invoke("coverage_experiment_create",{...scope,hypothesis:"operator"});
    await transport.invoke("coverage_experiment_get",{id,scope});
    await transport.invoke("coverage_experiment_list",{...scope,limit:20,before:{created_at:"2026-09-08T01:02:03.123456789Z",id}});
    await transport.invoke("coverage_experiment_complete",{id,request:{scope,result_run_id:id}});
    await transport.invoke("coverage_experiment_cancel",{id,request:{scope,reason:"abandoned"}});
    expect(fetch.mock.calls.map(([url,init]) => [new URL(url).pathname,init.method])).toEqual([["/coverage/experiments","POST"],[`/coverage/experiments/${id}`,"GET"],["/coverage/experiments","GET"],[`/coverage/experiments/${id}/complete`,"POST"],[`/coverage/experiments/${id}/cancel`,"POST"]]);
    expect(new URL(fetch.mock.calls[2][0]).searchParams.get("before_created_at")).toBe("2026-09-08T01:02:03.123456789Z");
    expect(JSON.parse(fetch.mock.calls[3][1].body)).toEqual({scope,result_run_id:id});
  });
  it("uses bounded native raw envelopes only for the five experiment commands", async () => {
    const transport=createTauriTransport();
    for(const command of ["create","get","list","complete","cancel"]) {
      const args=command==="get"?{id,scope}:command==="complete"||command==="cancel"?{id,request:{scope}}:scope;
      await transport.invoke(`coverage_experiment_${command}`,args);
      expect(invoke.mock.lastCall?.[1]).toBeInstanceOf(Uint8Array);
      expect(JSON.parse(new TextDecoder().decode(invoke.mock.lastCall?.[1]))).toEqual(args);
    }
    await transport.invoke("run_history",{project:"/project"}); expect(invoke.mock.lastCall?.[1]).toEqual({project:"/project"});
  });
});
