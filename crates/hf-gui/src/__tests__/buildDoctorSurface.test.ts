import { afterEach, describe, expect, it, vi } from "vitest";
import { createHttpTransport } from "../lib/httpTransport";
import { enExtra, zhExtra } from "../i18n.extra";

afterEach(() => vi.unstubAllGlobals());

describe("build profile wire adapters", () => {
  it("maps profile CRUD, bounded history and the reviewed digest to REST", async () => {
    const requests: Array<{ url: string; method?: string; body: unknown }> = [];
    vi.stubGlobal("fetch", vi.fn(async (url: string, options: RequestInit) => {
      requests.push({ url, method: options.method, body: options.body ? JSON.parse(String(options.body)) : null });
      return new Response("null", { status: 200, headers: { "content-type": "application/json" } });
    }));
    const transport = createHttpTransport({ baseUrl: "http://localhost:8081" });
    await transport.invoke("build_profile", { project: "/a b" });
    await transport.invoke("build_profile_set", { project: "/a b", componentRoot: ".", buildSystem: "cmake", compileDatabasePath: "build/compile_commands.json", cmakeDefinitions: { BUILD_TESTING: "OFF" }, dependencies: [{ kind: "pkg_config", name: "zlib" }] });
    await transport.invoke("build_history", { project: "/a b", limit: 20 });
    await transport.invoke("build_run", { project: "/a b", expectedProfileSha256: "reviewed" });
    await transport.invoke("build_profile_clear", { project: "/a b" });
    expect(requests).toEqual([
      { url: "http://localhost:8081/build/profile?project=%2Fa+b", method: "GET", body: null },
      { url: "http://localhost:8081/build/profile", method: "PUT", body: { project: "/a b", component_root: ".", build_system: "cmake", compile_database_path: "build/compile_commands.json", cmake_definitions: { BUILD_TESTING: "OFF" }, dependencies: [{ kind: "pkg_config", name: "zlib" }] } },
      { url: "http://localhost:8081/build/history?project=%2Fa+b&limit=20", method: "GET", body: null },
      { url: "http://localhost:8081/build/run", method: "POST", body: { project: "/a b", expected_profile_sha256: "reviewed" } },
      { url: "http://localhost:8081/build/profile", method: "DELETE", body: { project: "/a b" } },
    ]);
  });
  it("pairs all build profile states and terminal outcomes in both languages", () => {
    for (const key of ["unconfigured", "needs_build", "ready", "stale", "invalid"].map((state) => `buildDoctor.profileState.${state}`).concat(["succeeded", "step_failed", "timed_out", "cancelled", "artifact_missing", "artifact_invalid", "runtime_failed", "denied", "profile_changed"].map((state) => `buildDoctor.runStatus.${state}`))) {
      expect(enExtra[key], key).toBeTruthy();
      expect(zhExtra[key], key).toBeTruthy();
    }
  });
});
