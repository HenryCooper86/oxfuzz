import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

function source(relativePath: string): string {
  return readFileSync(new URL(relativePath, import.meta.url), "utf8");
}

describe("service-owned oracle studio surface", () => {
  it("declares the serialized specification and scaffold view", () => {
    const types = source("../types/index.ts");
    expect(types).toContain("interface OracleSpec");
    expect(types).toContain("interface OracleScaffoldView");
    expect(types).toContain("type OracleKind");
    expect(types).toContain("OracleProperty");
    expect(types).toContain("blocking_lint");
    expect(types).toContain('"round_trip"');
  });

  it("shows the whole scaffold before anything is built", () => {
    const panel = source("../components/OracleStudioPanel.tsx");
    expect(panel).toContain("view.source");
    expect(panel).toContain("oracleStudio.reviewNotice");
    // The scaffold is produced by the service, not assembled here.
    expect(panel).toContain('invoke<OracleScaffoldView>("oracle_scaffold"');
    expect(panel).not.toContain("LLVMFuzzerTestOneInput");
    expect(panel).not.toContain("__builtin_trap");
  });

  it("surfaces a scaffold the lint would refuse rather than offering it", () => {
    const panel = source("../components/OracleStudioPanel.tsx");
    expect(panel).toContain("view.blocking_lint");
    expect(panel).toContain("oracleStudio.blockingLint");
  });

  it("collects each property's symbols and never builds from the panel", () => {
    const panel = source("../components/OracleStudioPanel.tsx");
    expect(panel).toContain("differential");
    expect(panel).toContain("round_trip");
    expect(panel).toContain("invariant");
    // Building and running stay on the existing approved paths.
    expect(panel).not.toContain('invoke("harness_compile"');
    expect(panel).not.toContain('invoke("run_fuzzer"');
  });

  it("keeps REST and Tauri as transports", () => {
    const transport = source("../lib/httpTransport.ts");
    expect(transport).toContain('path: "/oracles/scaffold"');
    expect(transport).toContain('path: "/findings/{crash_id}/oracle-violation"');
    const commands = source("../../src-tauri/src/commands.rs");
    expect(commands).toContain("pub async fn oracle_scaffold");
    expect(commands).toContain("pub async fn oracle_violation");
    expect(source("../../../hf-web/src/router.rs")).toContain('.route("/oracles/scaffold"');
  });

  it("is mounted in the harness view", () => {
    expect(source("../views/HarnessView.tsx")).toContain("OracleStudioPanel");
  });

  it("keeps English and Chinese oracle labels paired", () => {
    const translations = source("../i18n.extra.ts");
    expect(translations).toContain('"oracleStudio.title": "Oracle Studio"');
    expect(translations).toContain('"oracleStudio.title": "断言工作台"');
    expect(translations).toContain('"oracleStudio.kind.round_trip": "Round trip"');
    expect(translations).toContain('"oracleStudio.kind.round_trip": "往返一致性"');
  });
});
