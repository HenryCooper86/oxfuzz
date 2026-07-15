export type ConfirmationFocusTarget = "cancel" | "confirm";
export type ConfirmationKeyboardAction = "cancel" | null;

export function confirmationFocusTarget(danger: boolean): ConfirmationFocusTarget {
  return danger ? "cancel" : "confirm";
}

export function confirmationKeyboardAction(key: string): ConfirmationKeyboardAction {
  return key === "Escape" ? "cancel" : null;
}
