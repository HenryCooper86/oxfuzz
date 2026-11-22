// Parity strings the always-loaded shell needs (sidebar, title bar,
// dashboard). The per-view parity dictionaries load with their views.
export const enParityShell: Record<string, string> = {
  "nav.binary": "Binary",
  "title.binary": "Binary-only Fuzzing",
  "parity.analysis.dashboard.replayPointer": "Stored crashes are replayed from Triage: use the regression check there.",
  "parity.analysis.dashboard.openTriage": "Open Triage",
};
export const zhParityShell: Record<string, string> = {
  "nav.binary": "二进制",
  "title.binary": "纯二进制模糊测试",
  "parity.analysis.dashboard.replayPointer": "请在\"分诊\"页使用\"重放已存崩溃(回归检查)\"来重放已存崩溃。",
  "parity.analysis.dashboard.openTriage": "打开分诊",
};
