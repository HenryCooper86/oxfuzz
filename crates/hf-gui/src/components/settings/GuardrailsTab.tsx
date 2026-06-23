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
    <div className="flex flex-col gap-4">
      <div>
        <h2 className="text-base font-semibold">Guardrails</h2>
        <p className="text-xs text-text-secondary mt-0.5">Human-in-the-loop approval policy for safety-first fuzzing. Generated harnesses are untrusted code and require approval before execution.</p>
      </div>

      <SettingsGroup title="Permission Mode">
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
      </SettingsGroup>

      <SettingsGroup title="HITL Approval Gates">
        <div className="flex items-center justify-between py-2">
          <div>
            <span className="text-xs text-text-primary">Harness compilation</span>
            <p className="text-xs text-text-muted">Require approval before compiling a generated harness in the sandbox.</p>
          </div>
          <Switch checked={requireHarnessApproval} onChange={setRequireHarnessApproval} />
        </div>
        <div className="flex items-center justify-between py-2">
          <div>
            <span className="text-xs text-text-primary">Fuzzer execution</span>
            <p className="text-xs text-text-muted">Require approval before starting a fuzz run.</p>
          </div>
          <Switch checked={requireRunApproval} onChange={setRequireRunApproval} />
        </div>
        <div className="flex items-center justify-between py-2">
          <div>
            <span className="text-xs text-text-primary">Bug report publication</span>
            <p className="text-xs text-text-muted">Require approval before publishing a drafted bug report.</p>
          </div>
          <Switch checked={requireBugReportApproval} onChange={setRequireBugReportApproval} />
        </div>
      </SettingsGroup>

      <SettingsGroup title="Risk Scoring">
        <SettingsItem label="HITL Threshold">
          <Input type="number" step="0.1" min="0" max="1" value={hitlThreshold} onChange={(e) => setHitlThreshold(parseFloat(e.target.value) || 0.6)} />
        </SettingsItem>
        <div className="flex gap-2 mt-2">
          <Badge variant="success">Low risk</Badge>
          <Badge variant="warning">Medium risk</Badge>
          <Badge variant="error">High risk</Badge>
          <span className="text-xs text-text-muted">Actions scoring above {hitlThreshold} require HITL approval.</span>
        </div>
      </SettingsGroup>

      <SettingsGroup title="Loop Detection">
        <div className="flex items-center justify-between py-2">
          <div>
            <span className="text-xs text-text-primary">Enable loop detection</span>
            <p className="text-xs text-text-muted">Detect and block repeated identical tool calls to prevent infinite loops.</p>
          </div>
          <Switch checked={loopDetection} onChange={setLoopDetection} />
        </div>
        {loopDetection && (
          <SettingsItem label="Max identical calls">
            <Input type="number" value={maxIdenticalCalls} onChange={(e) => setMaxIdenticalCalls(parseInt(e.target.value) || 3)} />
          </SettingsItem>
        )}
      </SettingsGroup>
    </div>
  );
}