import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import { I18nProvider } from "../i18n";
import { ManagedMutatorEvidence, type MutatorArtifact } from "../components/ManagedMutatorPanel";

describe("managed native mutator evidence", () => {
  it("shows retained identity and does not label unobserved trimming verified", () => {
    const artifact: MutatorArtifact = {
      version: 1, api: "afl_plus_plus", source_sha256: "a".repeat(64), artifact_name: "fuzz_parse.mutator.so",
      artifact_sha256: "b".repeat(64), sandbox_image_id: `sha256:${"c".repeat(64)}`, custom_trim: true,
      self_test: { exit_code: 0, mutation_observed: true, trim_observed: false, log: "mutation observed", log_truncated: false },
    };
    const html = renderToStaticMarkup(<I18nProvider><ManagedMutatorEvidence artifact={artifact} /></I18nProvider>);
    expect(html).toContain("Native mutation observed");
    expect(html).toContain("Custom trimming not observed");
    expect(html).toContain(artifact.artifact_sha256);
    expect(html).toContain(artifact.sandbox_image_id);
  });
});
