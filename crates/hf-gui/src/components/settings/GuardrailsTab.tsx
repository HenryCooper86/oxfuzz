// Guardrails tab -- HITL approval policy for safety-first fuzzing.
// Controlled: reads/writes the parsed `guardrails` config object via props.

import { Switch } from "../ui/Switch";
import { Input } from "../ui/Input";
import { Badge } from "../ui/Badge";
import { SettingsGroup, SettingsItem } from "../ui/SettingsGroup";
import { Shield, ShieldAlert, ShieldCheck } from "lucide-react";
import { useI18n } from "../../i18n";

type PermissionMode = "strict" | "auto" | "manual";
type Cfg = Record<string, unknown>;

export function GuardrailsTab({ value, onChange }: { value: Cfg; onChange: (next: Cfg) => void }) {
  const { t } = useI18n();
  const mode = ((value.permission_mode as string) ?? "strict") as PermissionMode;
  const hitlThreshold = (value.hitl_threshold as number) ?? 0.6;
  const maxIdenticalCalls = (value.max_identical_calls as number) ?? 3;
  const loopDetection = maxIdenticalCalls > 0;

  // HITL approval gates: persisted under a dedicated [hitl_gates] table so the
  // toggles round-trip. Unknown to current backend readers (harmless extra keys).
  const gates = (value.hitl_gates as Cfg) ?? {};
  const requireHarnessApproval = gates.harness !== false;
  const requireRunApproval = gates.run !== false;
  const requireBugReportApproval = gates.bug_report !== false;

  function patch(next: Cfg) {
    onChange({ ...value, ...next });
  }
  function patchGates(next: Cfg) {
    onChange({ ...value, hitl_gates: { ...gates, ...next } });
  }

  return (
    <div>
      <SettingsGroup title={t("settings.guardrails.permissionMode")} description={t("settings.guardrails.permissionModeDesc")}>
        <div style={{ padding: "10px 14px" }}>
        <div className="flex gap-2">
          {([
            { id: "strict", label: t("settings.guardrails.strict"), icon: Shield, desc: t("settings.guardrails.strictDesc") },
            { id: "auto", label: t("settings.guardrails.auto"), icon: ShieldCheck, desc: t("settings.guardrails.autoDesc") },
            { id: "manual", label: t("settings.guardrails.manual"), icon: ShieldAlert, desc: t("settings.guardrails.manualDesc") },
          ] as const).map((m) => (
            <button
              key={m.id}
              onClick={() => patch({ permission_mode: m.id })}
              className="flex flex-col gap-1 p-3 rounded-md transition-all duration-150 flex-1"
              style={{
                background: mode === m.id ? "var(--accent-subtle)" : "transparent",
                border: `1px solid ${mode === m.id ? "var(--accent)" : "var(--border)"}`,
                color: mode === m.id ? "var(--accent)" : "var(--text-muted)",
                cursor: "pointer",
                textAlign: "left",
              }}
            >
              <m.icon size={16} />
              <span className="text-xs font-medium">{m.label}</span>
              <span className="text-xs" style={{ opacity: 0.7 }}>{m.desc}</span>
            </button>
          ))}
        </div>
        </div>
      </SettingsGroup>

      <SettingsGroup title={t("settings.guardrails.approvalGates")}>
        <SettingsItem title={t("settings.guardrails.harnessGate")} description={t("settings.guardrails.harnessGateDesc")}>
          <Switch checked={requireHarnessApproval} onChange={(v) => patchGates({ harness: v })} />
        </SettingsItem>
        <SettingsItem title={t("settings.guardrails.runGate")} description={t("settings.guardrails.runGateDesc")}>
          <Switch checked={requireRunApproval} onChange={(v) => patchGates({ run: v })} />
        </SettingsItem>
        <SettingsItem title={t("settings.guardrails.bugReportGate")} description={t("settings.guardrails.bugReportGateDesc")}>
          <Switch checked={requireBugReportApproval} onChange={(v) => patchGates({ bug_report: v })} />
        </SettingsItem>
      </SettingsGroup>

      <SettingsGroup title={t("settings.guardrails.riskScoring")}>
        <SettingsItem title={t("settings.guardrails.hitlThreshold")}>
          <div style={{ width: 120 }}>
            <Input type="number" step="0.1" min="0" max="1" value={hitlThreshold} onChange={(e) => patch({ hitl_threshold: parseFloat(e.target.value) || 0.6 })} />
          </div>
        </SettingsItem>
        <div className="settings-item" style={{ padding: "10px 14px" }}>
          <div className="flex gap-2 items-center flex-wrap">
            <Badge variant="success">{t("settings.guardrails.lowRisk")}</Badge>
            <Badge variant="warning">{t("settings.guardrails.mediumRisk")}</Badge>
            <Badge variant="error">{t("settings.guardrails.highRisk")}</Badge>
            <span className="text-xs text-text-muted">{t("settings.guardrails.thresholdNote", { threshold: hitlThreshold })}</span>
          </div>
        </div>
      </SettingsGroup>

      <SettingsGroup title={t("settings.guardrails.loopDetection")}>
        <SettingsItem title={t("settings.guardrails.enableLoopDetection")} description={t("settings.guardrails.enableLoopDetectionDesc")}>
          <Switch checked={loopDetection} onChange={(v) => patch({ max_identical_calls: v ? 3 : 0 })} />
        </SettingsItem>
        {loopDetection && (
          <SettingsItem title={t("settings.guardrails.maxIdenticalCalls")}>
            <div style={{ width: 120 }}>
              <Input type="number" value={maxIdenticalCalls} onChange={(e) => patch({ max_identical_calls: parseInt(e.target.value) || 3 })} />
            </div>
          </SettingsItem>
        )}
      </SettingsGroup>
    </div>
  );
}
