import { describe, expect, it } from "vitest";
import { resolveWizardProvider } from "./wizardProvider";
import { PROVIDER_PRESETS } from "../../lib/providerPresets";

describe("resolveWizardProvider", () => {
  it("persists a native Ollama provider from defaults with no API key", () => {
    const p = resolveWizardProvider({ providerType: "ollama", apiKey: "", model: "", baseUrl: "" });
    expect(p).not.toBeNull();
    expect(p?.provider_type).toBe("ollama");
    // The native provider appends /api/chat, so the base URL must NOT carry /v1.
    expect(p?.base_url).toBe("http://localhost:11434");
    expect(p?.base_url).not.toContain("/v1");
    expect(p?.api_key).toBeNull();
    expect(p?.model).toBe(PROVIDER_PRESETS.ollama.model);
  });

  it("honors an explicit Ollama base URL the user typed", () => {
    const p = resolveWizardProvider({
      providerType: "ollama",
      apiKey: "",
      model: "qwen2.5:7b",
      baseUrl: "http://192.168.1.5:11434",
    });
    expect(p?.base_url).toBe("http://192.168.1.5:11434");
    expect(p?.model).toBe("qwen2.5:7b");
  });

  it("persists an Ollama Cloud provider at ollama.com with the API key", () => {
    const p = resolveWizardProvider({ providerType: "ollama-cloud", apiKey: "sk-cloud", model: "", baseUrl: "" });
    expect(p).not.toBeNull();
    expect(p?.provider_type).toBe("ollama-cloud");
    expect(p?.base_url).toBe("https://ollama.com");
    expect(p?.api_key).toBe("sk-cloud");
    expect(p?.model).toBe(PROVIDER_PRESETS["ollama-cloud"].model);
  });

  it("keeps the selected provider type instead of guessing from the URL", () => {
    const p = resolveWizardProvider({
      providerType: "openai-compat",
      apiKey: "sk-x",
      model: "llama-3.1-70b",
      baseUrl: "https://api.together.xyz/v1",
    });
    expect(p?.provider_type).toBe("openai-compat");
  });

  it("persists a standard OpenAI provider", () => {
    const p = resolveWizardProvider({
      providerType: "openai",
      apiKey: "sk-abc",
      model: "",
      baseUrl: "https://api.openai.com/v1",
    });
    expect(p?.provider_type).toBe("openai");
    expect(p?.api_key).toBe("sk-abc");
    expect(p?.model).toBe("gpt-4o");
  });

  it("returns null when there is nothing to persist (no key, no URL)", () => {
    const p = resolveWizardProvider({ providerType: "openai-compat", apiKey: "", model: "", baseUrl: "" });
    expect(p).toBeNull();
  });
});

describe("branded quick-start routing", () => {
  it("sends the Kimi Coding subscription key to the coding endpoint, not the public API", () => {
    const p = resolveWizardProvider({ providerType: "kimi-coding", apiKey: "sub-key", model: "", baseUrl: "" });
    expect(p?.provider_type).toBe("openai-compat");
    expect(p?.base_url).toBe("https://api.kimi.ai/coding/v1");
    // A subscription key must never reach the public platform endpoint.
    expect(p?.base_url).not.toContain("api.moonshot.");
    expect(p?.tool_calling_mode).toBe("native");
  });

  it("keeps GLM coding plans off the pay-as-you-go endpoints", () => {
    for (const selection of ["glm-coding", "zai-coding"]) {
      const p = resolveWizardProvider({ providerType: selection, apiKey: "plan-key", model: "", baseUrl: "" });
      expect(p?.provider_type).toBe("openai-compat");
      expect(p?.base_url).toContain("/coding/");
      expect(p?.base_url).not.toBe("https://open.bigmodel.cn/api/paas/v4");
      expect(p?.base_url).not.toBe("https://api.z.ai/api/paas/v4");
      expect(p?.tool_calling_mode).toBe("native");
    }
  });

  it("routes the Kimi public API through the OpenAI-compatible adapter with native tools", () => {
    const p = resolveWizardProvider({ providerType: "kimi-api", apiKey: "sk-kimi", model: "", baseUrl: "" });
    expect(p?.provider_type).toBe("openai-compat");
    expect(p?.base_url).toBe("https://api.moonshot.ai/v1");
    expect(p?.tool_calling_mode).toBe("native");
  });

  it("persists DeepSeek through its native backend type without a tool-mode override", () => {
    const p = resolveWizardProvider({ providerType: "deepseek", apiKey: "sk-ds", model: "", baseUrl: "" });
    expect(p?.provider_type).toBe("deepseek");
    expect(p?.base_url).toBe("https://api.deepseek.com");
    // provider_type "deepseek" already resolves native tool calling backend-side.
    expect(p?.tool_calling_mode).toBeNull();
  });

  it("honors an edited coding endpoint and model instead of forcing preset values", () => {
    const p = resolveWizardProvider({
      providerType: "zai-coding",
      apiKey: "plan-key",
      model: "glm-5.3-flash",
      baseUrl: "https://api.z.ai/api/coding/paas/v4",
    });
    expect(p?.base_url).toBe("https://api.z.ai/api/coding/paas/v4");
    expect(p?.model).toBe("glm-5.3-flash");
  });

  it("falls back to a plain OpenAI-compatible provider for unknown selections", () => {
    const p = resolveWizardProvider({
      providerType: "not-a-real-provider",
      apiKey: "sk-x",
      model: "m",
      baseUrl: "https://relay.example/v1",
    });
    expect(p?.provider_type).toBe("openai-compat");
    expect(p?.base_url).toBe("https://relay.example/v1");
    expect(p?.tool_calling_mode).toBeNull();
  });
});
