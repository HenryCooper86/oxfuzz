const SECRET_FIELD_NAMES = new Set([
  "api_key",
  "api_token",
  "access_token",
  "auth_token",
  "bearer_token",
  "client_secret",
  "password",
  "passphrase",
  "private_key",
  "secret",
  "token",
]);

const SECRET_HEADER_NAMES = new Set([
  "api-key",
  "authorization",
  "authentication",
  "proxy-authorization",
  "x-api-key",
  "x-auth-token",
]);

function normalizeName(name: string): string {
  return name.trim().toLowerCase().replace(/[.-]+/g, "_");
}

/** Return whether a config field contains credential material, not its env-var name. */
export function isSecretFieldName(name: string): boolean {
  const normalized = normalizeName(name);
  if (normalized.endsWith("_env") || normalized.includes("_env_")) return false;
  if (SECRET_FIELD_NAMES.has(normalized)) return true;
  return [...SECRET_FIELD_NAMES].some((secret) => normalized.endsWith(`_${secret}`));
}

/** Return whether an HTTP header value normally carries authentication material. */
export function isSecretHeaderName(name: string): boolean {
  const normalized = name.trim().toLowerCase();
  return SECRET_HEADER_NAMES.has(normalized)
    || normalized.endsWith("-api-key")
    || normalized.endsWith("-auth-token");
}
