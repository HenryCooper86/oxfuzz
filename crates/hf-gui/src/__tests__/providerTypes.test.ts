import { describe, expect, it } from "vitest";
import { normalizeProvider } from "../components/settings/providerTypes";

describe("provider settings normalization", () => {
  it("preserves browser-safe configured-state flags for hidden credentials", () => {
    const provider = normalizeProvider({
      id: "remote",
      api_key_configured: true,
      api_key_env_configured: false,
      headers_configured: true,
    });

    expect(provider.api_key).toBeNull();
    expect(provider.headers).toEqual({});
    expect(provider.api_key_configured).toBe(true);
    expect(provider.api_key_env_configured).toBe(false);
    expect(provider.headers_configured).toBe(true);
  });

  it("derives configured-state flags for trusted desktop responses", () => {
    expect(normalizeProvider({ api_key: "synthetic-key" }).api_key_configured).toBe(true);
    expect(normalizeProvider({ api_key_env: "SYNTHETIC_KEY" }).api_key_env_configured).toBe(true);
    expect(normalizeProvider({ headers: { Authorization: "synthetic" } }).headers_configured).toBe(true);
    expect(normalizeProvider({}).api_key_configured).toBe(false);
  });
});
