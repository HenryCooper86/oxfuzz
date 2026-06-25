// Guardrails tab -- HITL approval policy for safety-first fuzzing.

import { useState } from "react";
import { Switch } from "../ui/Switch";
import { Input } from "../ui/Input";
import { Badge } from "../ui/Badge";
import { SettingsGroup, SettingsItem } from "../ui/SettingsGroup";
import { Shield, ShieldAlert, ShieldCheck } from "lucide-react";

type PermissionMode = "strict" | "auto" | "manual";

export function GuardrailsTab() {
  const [mode, setMode] = useState<PermissionMode>("strict");
  const [hitlThreshold, setHitlThreshold] = useState(0.6);
  const [maxIdenticalCalls, setMaxIdenticalCalls] = useState(3);
  const [requireHarnessApproval, setRequireHarnessApproval] = useState(true);
  const [requireRunApproval, setRequireRunApproval] = useState(true);
  const [requireBugReportApproval, setRequireBugReportApproval] = useState(true);
  const [loopDetection, setLoopDetection] = useState(true);

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
              onClick={() => setMode(m.id)}
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
          <Switch checked={requireHarnessApproval} onChange={setRequireHarnessApproval} />
        </SettingsItem>
        <SettingsItem title="Fuzzer execution" description="Require approval before starting a fuzz run.">
          <Switch checked={requireRunApproval} onChange={setRequireRunApproval} />
        </SettingsItem>
        <SettingsItem title="Bug report publication" description="Require approval before publishing a drafted bug report.">
          <Switch checked={requireBugReportApproval} onChange={setRequireBugReportApproval} />
        </SettingsItem>
      </SettingsGroup>

      <SettingsGroup title="Risk Scoring">
        <SettingsItem title="HITL Threshold">
          <div style={{ width: 120 }}>
            <Input type="number" step="0.1" min="0" max="1" value={hitlThreshold} onChange={(e) => setHitlThreshold(parseFloat(e.target.value) || 0.6)} />
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
          <Switch checked={loopDetection} onChange={setLoopDetection} />
        </SettingsItem>
        {loopDetection && (
          <SettingsItem title="Max identical calls">
            <div style={{ width: 120 }}>
              <Input type="number" value={maxIdenticalCalls} onChange={(e) => setMaxIdenticalCalls(parseInt(e.target.value) || 3)} />
            </div>
          </SettingsItem>
        )}
      </SettingsGroup>
    </div>
  );
}