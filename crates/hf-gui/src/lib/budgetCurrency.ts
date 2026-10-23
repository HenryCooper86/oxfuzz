/** Exact USD presentation; storage and admission continue to use integer micro-USD. */
export function formatMicroUsd(microUsd: string): string {
  const digits = BigInt(microUsd).toString().padStart(7, "0");
  const whole = digits.slice(0, -6);
  const fraction = digits.slice(-6).replace(/0+$/, "").padEnd(2, "0");
  return `${whole}.${fraction}`;
}

type UsdLimit = { valid: true; microUsd: string | undefined } | { valid: false };

export function parseUsdLimit(text: string): UsdLimit {
  if (text === "") return { valid: true, microUsd: undefined };
  if (!/^(?:\d+(?:\.\d{0,6})?|\.\d{1,6})$/.test(text)) return { valid: false };
  const [whole, fraction = ""] = text.split(".");
  const amount = BigInt(`${whole || "0"}${fraction.padEnd(6, "0")}`);
  return amount > 0n ? { valid: true, microUsd: amount.toString() } : { valid: false };
}
