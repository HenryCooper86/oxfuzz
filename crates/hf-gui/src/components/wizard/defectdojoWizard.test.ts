import { describe, expect, it } from "vitest";
import { DD_STATE_VARIANT, defectDojoRemotePatch } from "./defectdojoWizard";
import type { DefectDojoDraft } from "../../lib/integrationSettings";

function baseDraft(): DefectDojoDraft {
  return {
    url: "https://old.example.com",
    api_token: { configured: true, change: "keep", replacement: "" },
    api_token_env: { configured: false, change: "keep", replacement: "" },
    verify_tls: false,
    product_name: "",
    product_type_name: "",
    engagement_name: "",
    auto_create: true,
    reimport: true,
    lifecycle: {
      autostart: true,
      compose_project: { configured: false, change: "keep", replacement: "" },
      compose_files: { configured: false, change: "keep", replacement: "" },
      startup_timeout_secs: null,
    },
  };
}

describe("defectDojoRemotePatch", () => {
  it("replaces the URL and the token when a new token is given", () => {
    const patch = defectDojoRemotePatch(baseDraft(), "  https://dojo.local:8080 ", " tok-123 ");
    expect(patch.url).toBe("https://dojo.local:8080");
    expect(patch.api_token).toEqual({ operation: "replace", value: "tok-123" });
  });

  it("keeps the existing token when the field is left blank", () => {
    const patch = defectDojoRemotePatch(baseDraft(), "https://dojo.local", "");
    expect(patch.url).toBe("https://dojo.local");
    // A "keep" change omits the api_token key entirely, preserving the stored token.
    expect(patch.api_token).toBeUndefined();
  });

  it("maps every lifecycle state to a valid Badge variant", () => {
    for (const variant of Object.values(DD_STATE_VARIANT)) {
      expect(["success", "warning", "error", "default"]).toContain(variant);
    }
    expect(DD_STATE_VARIANT.ready).toBe("success");
    expect(DD_STATE_VARIANT.docker_down).toBe("error");
  });
});
