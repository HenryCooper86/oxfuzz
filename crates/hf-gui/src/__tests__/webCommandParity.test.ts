// @vitest-environment jsdom
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { createHttpTransport, DESKTOP_ONLY_COMMANDS, isWebCommand } from "../lib/httpTransport";

/** Every `invoke("name"` / `invoke<T>("name"` call outside the tests. */
function invokedCommands(): Set<string> {
  const root = join(__dirname, "..");
  const names = new Set<string>();
  const walk = (dir: string) => {
    for (const entry of readdirSync(dir)) {
      const path = join(dir, entry);
      if (statSync(path).isDirectory()) {
        if (entry !== "__tests__") walk(path);
      } else if (/\.tsx?$/.test(entry)) {
        for (const match of readFileSync(path, "utf8").matchAll(/invoke(?:<[^()]*>)?\(\s*"([a-z_0-9]+)"/g)) {
          names.add(match[1]);
        }
      }
    }
  };
  walk(root);
  return names;
}

describe("browser command parity", () => {
  it("routes every command the GUI invokes, or names it desktop-only", () => {
    // The browser GUI showed "Unsupported command in web mode" for 50 of the
    // commands the desktop app answered; a new one must not slip in silently.
    const missing = [...invokedCommands()].filter((name) => !isWebCommand(name) && !DESKTOP_ONLY_COMMANDS.has(name)).sort();
    expect(missing).toEqual([]);
  });

  it("keeps no stale desktop-only entry", () => {
    const invoked = invokedCommands();
    expect([...DESKTOP_ONLY_COMMANDS].filter((name) => !invoked.has(name))).toEqual([]);
  });
});

describe("browser routes of the formerly desktop-only commands", () => {
  const calls: Array<{ path: string; method: string; body: unknown }> = [];
  const originalFetch = globalThis.fetch;
  afterEach(() => { globalThis.fetch = originalFetch; calls.length = 0; vi.unstubAllGlobals(); });

  function stubFetch(reply: unknown = {}) {
    globalThis.fetch = (async (url: RequestInfo | URL, init?: RequestInit) => {
      calls.push({
        path: new URL(String(url)).pathname,
        method: init?.method ?? "GET",
        body: init?.body ? JSON.parse(String(init.body)) : undefined,
      });
      return new Response(JSON.stringify(reply), { status: 200 });
    }) as typeof fetch;
  }

  it("maps path parameters and keeps nested campaign options as the desktop form sends them", async () => {
    stubFetch();
    const transport = createHttpTransport();
    await transport.invoke("run_campaign", { options: { project: "/p", engine: "libfuzzer", durationSecs: 60, iterations: 2 } });
    await transport.invoke("run_ci_gate", { project: "/p", target: "parse", engine: "libfuzzer", durationSecs: 30 });
    await transport.invoke("campaign_trust_report", { runId: "r1" });
    await transport.invoke("capture_run_edges", { runId: "r1" });
    await transport.invoke("thaw_provider", { providerId: "deepseek" });
    await transport.invoke("run_detail", { runId: "59a1f8f0" });
    await transport.invoke("clang_analysis_status", { operationId: "op1" });
    expect(calls.map(({ path, method }) => [path, method])).toEqual([
      ["/campaign/run", "POST"],
      ["/ci-gate", "POST"],
      ["/runs/r1/trust", "GET"],
      ["/runs/r1/edges", "POST"],
      ["/providers/deepseek/thaw", "POST"],
      ["/runs/detail/59a1f8f0", "GET"],
      ["/clang/analysis/op1", "GET"],
    ]);
    expect(calls[0].body).toEqual({ options: { project: "/p", engine: "libfuzzer", durationSecs: 60, iterations: 2 } });
    expect(calls[1].body).toEqual({ project: "/p", target: "parse", engine: "libfuzzer", duration_secs: 30 });
  });

  function stubDownload() {
    const saved: Array<{ name: string; text: Promise<string> }> = [];
    vi.stubGlobal("URL", Object.assign(URL, {
      createObjectURL: (blob: Blob) => { saved.push({ name: "", text: blob.text() }); return "blob:x"; },
      revokeObjectURL: () => undefined,
    }));
    const click = vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(function (this: HTMLAnchorElement) {
      saved[saved.length - 1].name = this.download;
    });
    return { saved, click };
  }

  it("saves text files as a browser download", async () => {
    const { saved } = stubDownload();
    const name = await createHttpTransport().invoke<string | null>("save_text_file", {
      fileName: "campaign.sarif", extensions: ["sarif"], contents: "{}",
    });
    expect(name).toBe("campaign.sarif");
    expect(saved[0].name).toBe("campaign.sarif");
    expect(await saved[0].text).toBe("{}");
  });

  it("downloads the line-coverage report in the asked format", async () => {
    stubFetch({ lcov: "SF:a.c\nend_of_record\n", html: "<html></html>", lines_hit: 86, lines_total: 5758, files: 3, skipped_files: 0 });
    const { saved } = stubDownload();
    const outcome = await createHttpTransport().invoke<Record<string, unknown>>("export_coverage_line_report", {
      project: "/p", target: "ares create", format: "lcov",
    });
    expect(calls.map(({ path }) => path)).toEqual(["/coverage/line-report"]);
    expect(calls[0].body).toEqual({ project: "/p", target: "ares create" });
    expect(saved[0].name).toBe("oxfuzz_ares_create.lcov.info");
    expect(await saved[0].text).toBe("SF:a.c\nend_of_record\n");
    expect(outcome).toEqual({ path: "oxfuzz_ares_create.lcov.info", lines_hit: 86, lines_total: 5758, files: 3, skipped_files: 0 });
  });
});
