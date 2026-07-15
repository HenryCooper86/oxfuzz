import type { SectionId } from "../components/settings/settingsSections";

export interface SettingsLoadToken {
  requestId: number;
  sectionId: SectionId;
}

export interface SettingsSectionState {
  requestId: number;
  requestedSection: SectionId;
  loadedSection: SectionId | null;
  value: unknown;
  raw: string;
  dirty: boolean;
  loading: boolean;
  error: string | null;
}

export function beginSettingsSectionLoad(
  requestId: number,
  requestedSection: SectionId,
): SettingsSectionState {
  return {
    requestId,
    requestedSection,
    loadedSection: null,
    value: null,
    raw: "",
    dirty: false,
    loading: true,
    error: null,
  };
}

export function isMatchingSettingsLoad(
  state: SettingsSectionState,
  token: SettingsLoadToken,
): boolean {
  return state.requestId === token.requestId
    && state.requestedSection === token.sectionId;
}

export function completeSettingsSectionLoad(
  state: SettingsSectionState,
  token: SettingsLoadToken,
  value: unknown,
  raw: string,
): SettingsSectionState {
  if (!isMatchingSettingsLoad(state, token)) return state;
  return {
    ...state,
    loadedSection: token.sectionId,
    value,
    raw,
    dirty: false,
    loading: false,
    error: null,
  };
}

export function failSettingsSectionLoad(
  state: SettingsSectionState,
  token: SettingsLoadToken,
  error: string,
): SettingsSectionState {
  if (!isMatchingSettingsLoad(state, token)) return state;
  return {
    ...state,
    loadedSection: null,
    value: null,
    raw: "",
    dirty: false,
    loading: false,
    error,
  };
}

export function isSettingsSectionReady(
  state: SettingsSectionState,
  activeSection: SectionId,
): boolean {
  return state.loadedSection === activeSection
    && state.requestedSection === activeSection
    && !state.loading
    && state.error === null;
}

export async function confirmSettingsNavigation(
  dirty: boolean,
  requestConfirmation: () => Promise<boolean>,
): Promise<boolean> {
  return !dirty || requestConfirmation();
}
