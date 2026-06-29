// Guardrails tab -- HITL approval policy for safety-first fuzzing.
// Controlled: reads/writes the parsed `guardrails` config object via props.

import { Switch } from "../ui/Switch";
import { Input } from "../ui/Input";
import { Badge } from "../ui/Badge";
import { SettingsGroup, SettingsItem } from "../ui/SettingsGroup";
import { Shield, ShieldAlert, ShieldCheck } from "lucide-react";

type PermissionMode = "strict" | "auto" | "manual";
type Cfg = Record<string, unknown>;

export function GuardrailsTab({ value, onChange }: { value: Cfg; onChange: (next: Cfg) => void }) {
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
      <SettingsGroup title="Permission Mode" description="Human-in-the-loop approval policy for safety-first fuzzing. Generated harnesses are untrusted code and require approval before execution.">
        <div style={{ padding: "10px 14px" }}>
        <div className="flex gap-2">
          {([
            { id: "strict", label: "Strict (recommended)", icon: Shield, desc: "HITL on all high-risk actions" },
            { id: "auto", label: "Auto", icon: ShieldCheck, desc: "No HITL -- automated fuzzing" },
            { id: "manual", label: "Manual", icon: ShieldAlert, desc: "HITL on every action" },
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

      <SettingsGroup title="HITL Approval Gates">
        <SettingsItem title="Harness compilation" description="Require approval before compiling a generated harness in the sandbox.">
          <Switch checked={requireHarnessApproval} onChange={(v) => patchGates({ harness: v })} />
        </SettingsItem>
        <SettingsItem title="Fuzzer execution" description="Require approval before starting a fuzz run.">
          <Switch checked={requireRunApproval} onChange={(v) => patchGates({ run: v })} />
        </SettingsItem>
        <SettingsItem title="Bug report publication" description="Require approval before publishing a drafted bug report.">
          <Switch checked={requireBugReportApproval} onChange={(v) => patchGates({ bug_report: v })} />
        </SettingsItem>
      </SettingsGroup>

      <SettingsGroup title="Risk Scoring">
        <SettingsItem title="HITL Threshold">
          <div style={{ width: 120 }}>
            <Input type="number" step="0.1" min="0" max="1" value={hitlThreshold} onChange={(e) => patch({ hitl_threshold: parseFloat(e.target.value) || 0.6 })} />
          </div>
        </SettingsItem>
        <div className="settings-item" style={{ padding: "10px 14px" }}>
          <div className="flex gap-2 items-center flex-wrap">
            <Badge variant="success">Low risk</Badge>
            <Badge variant="warning">Medium risk</Badge>
            <Badge variant="error">High risk</Badge>
            <span className="text-xs text-text-muted">Actions scoring above {hitlThreshold} require HITL approval.</span>
          </div>
        </div>
      </SettingsGroup>

      <SettingsGroup title="Loop Detection">
        <SettingsItem title="Enable loop detection" description="Detect and block repeated identical tool calls to prevent infinite loops.">
          <Switch checked={loopDetection} onChange={(v) => patch({ max_identical_calls: v ? 3 : 0 })} />
        </SettingsItem>
        {loopDetection && (
          <SettingsItem title="Max identical calls">
            <div style={{ width: 120 }}>
              <Input type="number" value={maxIdenticalCalls} onChange={(e) => patch({ max_identical_calls: parseInt(e.target.value) || 3 })} />
            </div>
          </SettingsItem>
        )}
      </SettingsGroup>
    </div>
  );
}
