/**
 * A model cost for display, or `null` when tokens were used but no cost was
 * recorded: the model has no configured price, so the amount is unknown, not
 * zero.
 */
export function formatCost(costUsd: number, tokens: number): string | null {
  if (costUsd > 0) return `$${costUsd.toFixed(costUsd < 0.01 ? 4 : 2)}`;
  return tokens > 0 ? null : "$0";
}
