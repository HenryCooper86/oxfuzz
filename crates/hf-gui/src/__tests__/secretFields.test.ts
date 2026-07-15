import { describe, expect, it } from "vitest";
import { isSecretFieldName, isSecretHeaderName } from "../lib/secretFields";

describe("secret field detection", () => {
  it("masks direct credential fields but leaves environment-variable names visible", () => {
    expect(isSecretFieldName("api_token")).toBe(true);
    expect(isSecretFieldName("client_secret")).toBe(true);
    expect(isSecretFieldName("password")).toBe(true);
    expect(isSecretFieldName("api_token_env")).toBe(false);
    expect(isSecretFieldName("secret_env_name")).toBe(false);
    expect(isSecretFieldName("base_url")).toBe(false);
  });

  it("masks standard and vendor-specific authentication headers", () => {
    expect(isSecretHeaderName("Authorization")).toBe(true);
    expect(isSecretHeaderName("Proxy-Authorization")).toBe(true);
    expect(isSecretHeaderName("X-API-Key")).toBe(true);
    expect(isSecretHeaderName("api-key")).toBe(true);
    expect(isSecretHeaderName("Content-Type")).toBe(false);
    expect(isSecretHeaderName("X-Request-ID")).toBe(false);
  });
});
