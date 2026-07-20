// Pure helper for the wizard's DefectDojo step. Kept in a .ts module so the
// component file exports only a component (react-refresh/only-export-components)
// and so the patch construction is unit-testable.

import {
  defectDojoPatchFromDraft,
  type DefectDojoConfigPatch,
  type DefectDojoDraft,
} from "../../lib/integrationSettings";
import type { DefectDojoState } from "../../types";

// Badge variant per lifecycle state (Badge supports default/accent/success/
// error/warning).
export const DD_STATE_VARIANT: Record<DefectDojoState, "success" | "warning" | "error" | "default"> = {
  ready: "success",
  remote: "success",
  starting: "warning",
  stopped: "warning",
  not_installed: "default",
  not_configured: "default",
  docker_down: "error",
};

// Apply the wizard's remote URL and optional new token onto the loaded draft,
// leaving every other configured field untouched, and return the config patch.
// A blank token keeps the existing one (change stays "keep").
export function defectDojoRemotePatch(
  draft: DefectDojoDraft,
  url: string,
  token: string,
): DefectDojoConfigPatch {
  const nextToken = token.trim()
    ? { ...draft.api_token, change: "replace" as const, replacement: token.trim() }
    : draft.api_token;
  return defectDojoPatchFromDraft({ ...draft, url: url.trim(), api_token: nextToken });
}
