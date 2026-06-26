// Setup Wizard -- first-run onboarding for safety-first fuzzing.
// Modeled after y-agent's SetupWizard with 6 steps.

import { useState, type ReactNode } from "react";
import { Crosshair, Server, Shield, Database, CheckCircle2, ArrowRight, ArrowLeft } from "lucide-react";
import { Button } from "../ui/Button";
import { Input } from "../ui/Input";
import { Switch } from "../ui/Switch";
import { Badge } from "../ui/Badge";
import { Separator } from "../ui/Separator";
import { useToast } from "../ui/Toast";
import { getTransport } from "../../lib";
import { normalizeProvider, type Provider } from "../settings/providerTypes";

type Step = "welcome" | "providers" | "runtime" | "guardrails" | "storage" | "complete";

const STEPS: { id: Step; label: string; icon: ReactNode }[] = [
  { id: "welcome", label: "Welcome", icon: <Crosshair size={16} /> },
  { id: "providers", label: "Providers", icon: <Server size={16} /> },
  { id: "runtime", label: "Sandbox", icon: <Shield size={16} /> },
  { id: "guardrails", label: "Guardrails", icon: <Shield size={16} /> },
  { id: "storage", label: "Storage", icon: <Database size={16} /> },
  { id: "complete", label: "Complete", icon: <CheckCircle2 size={16} /> },
];

export function SetupWizard({ onComplete }: { onComplete: () => void }) {
  const { toast } = useToast();
  const [step, setStep] = useState<Step>("welcome");
  const [saving, setSaving] = useState(false);
  const stepIdx = STEPS.findIndex((s) => s.id === step);

  // Config state
  const [apiKey, setApiKey] = useState("");
  const [model, setModel] = useState("gpt-4o");
  const [baseUrl, setBaseUrl] = useState("https://api.openai.com/v1");
  const [useDocker, setUseDocker] = useState(true);
  const [requireHarnessApproval, setRequireHarnessApproval] = useState(true);
  const [requireRunApproval, setRequireRunApproval] = useState(true);

  function next() {
    const nextIdx = stepIdx + 1;
    if (nextIdx < STEPS.length) setStep(STEPS[nextIdx].id);
  }
  function prev() {
    const prevIdx = stepIdx - 1;
    if (prevIdx >= 0) setStep(STEPS[prevIdx].id);
  }
  async function finish() {
    if (saving) return;
    setSaving(true);
    try {
      // Persist the provider to the backend (config/providers.toml) so harness
      // generation and chat actually have an LLM. Without this the key only
      // lived in localStorage and never reached the service layer.
      const key = apiKey.trim();
      const url = baseUrl.trim();
      if (key || url) {
        const provider: Provider = normalizeProvider({
          id: "default",
          provider_type: /(^|\.)openai\.com/.test(url) ? "openai" : "openai-compat",
          model: model.trim() || "gpt-4o",
          base_url: url,
          api_key: key,
          tags: ["general", "reasoning", "code"],
        });
        await getTransport().invoke("set_providers", { providers: [provider] });
      }
      // ChatView reads the preferred model from localStorage; the API key now
      // lives only in the backend config, not in the browser store.
      localStorage.setItem("hf_provider_model", model);
      localStorage.setItem("hf_setup_completed", "true");
      onComplete();
    } catch (e) {
      toast({ title: "Setup save failed", description: String(e), variant: "error" });
      setSaving(false);
    }
  }

  return (
    <div className="flex h-full w-full items-center justify-center bg-surface-tertiary">
      <div
        className="surface-card flex flex-col"
        style={{
          width: 520,
          maxHeight: "calc(100vh - 64px)",
          padding: "var(--space-lg)",
          animation: "dialogContentIn 0.3s cubic-bezier(0.34,1.56,0.64,1)",
        }}
      >
        {/* Logo + title */}
        <div className="flex items-center gap-3 mb-4">
          <div
            className="flex items-center justify-center rounded-full"
            style={{ width: "40px", height: "40px", background: "var(--accent-subtle)", border: "1px solid var(--border)" }}
          >
            <Crosshair size={20} style={{ color: "var(--accent)" }} />
          </div>
          <div>
            <h1 className="text-base font-semibold">hobot_fuzz Setup</h1>
            <p className="text-xs text-text-secondary">Configure your AI fuzzing agent</p>
          </div>
        </div>

        {/* Step indicator */}
        <div className="flex items-center gap-1 mb-4">
          {STEPS.map((s, i) => (
            <div key={s.id} className="flex items-center gap-1 flex-1">
              <div
                className="flex items-center justify-center rounded-full shrink-0"
                style={{
                  width: "24px", height: "24px",
                  fontSize: "11px", fontWeight: 600,
                  background: i < stepIdx ? "rgba(111,207,151,0.15)" : i === stepIdx ? "var(--accent-subtle)" : "var(--surface-active)",
                  border: `1px solid ${i < stepIdx ? "var(--success)" : i === stepIdx ? "var(--accent)" : "var(--border)"}`,
                  color: i < stepIdx ? "var(--success)" : i === stepIdx ? "var(--accent)" : "var(--text-muted)",
                  transition: "all 0.2s ease",
                }}
              >
                {i < stepIdx ? <CheckCircle2 size={12} /> : i + 1}
              </div>
              {i < STEPS.length - 1 && (
                <div style={{ flex: 1, height: "2px", background: i < stepIdx ? "var(--success)" : "var(--border)", transition: "background 0.2s ease" }} />
              )}
            </div>
          ))}
        </div>

        {/* Step content */}
        <div className="flex-1 overflow-y-auto">
          {step === "welcome" && (
            <div className="flex flex-col gap-3">
              <h2 className="text-sm font-semibold">Welcome to hobot_fuzz</h2>
              <p className="text-xs text-text-secondary leading-relaxed">
                hobot_fuzz is an AI fuzzing agent that discovers targets, writes harnesses, and drives
                fuzzing engines (AFL++, honggfuzz, libFuzzer) in a sandboxed environment.
              </p>
              <p className="text-xs text-text-secondary leading-relaxed">
                This wizard will guide you through 4 configuration steps to get started safely.
              </p>
              <Separator />
              <div className="flex flex-col gap-1 text-xs text-text-muted">
                <span className="flex items-center gap-2"><Crosshair size={12} style={{ color: "var(--accent)" }} /> Discover fuzzing targets in C/C++ projects</span>
                <span className="flex items-center gap-2"><Crosshair size={12} style={{ color: "var(--accent)" }} /> Generate and compile harnesses in a sandbox</span>
                <span className="flex items-center gap-2"><Crosshair size={12} style={{ color: "var(--accent)" }} /> Run AFL++, honggfuzz, or libFuzzer</span>
                <span className="flex items-center gap-2"><Crosshair size={12} style={{ color: "var(--accent)" }} /> Triage crashes and draft bug reports</span>
              </div>
            </div>
          )}

          {step === "providers" && (
            <div className="flex flex-col gap-3">
              <h2 className="text-sm font-semibold">LLM Provider</h2>
              <p className="text-xs text-text-secondary">Configure the LLM backend for harness generation and crash triage.</p>
              <div className="flex flex-col gap-2">
                <div>
                  <label className="text-xs text-text-muted uppercase mb-1 block" style={{ fontWeight: 600, letterSpacing: "0.05em" }}>API Key</label>
                  <Input type="password" value={apiKey} onChange={(e) => setApiKey(e.target.value)} placeholder="sk-..." />
                </div>
                <div>
                  <label className="text-xs text-text-muted uppercase mb-1 block" style={{ fontWeight: 600, letterSpacing: "0.05em" }}>Model</label>
                  <Input value={model} onChange={(e) => setModel(e.target.value)} placeholder="gpt-4o" mono />
                </div>
                <div>
                  <label className="text-xs text-text-muted uppercase mb-1 block" style={{ fontWeight: 600, letterSpacing: "0.05em" }}>Base URL</label>
                  <Input value={baseUrl} onChange={(e) => setBaseUrl(e.target.value)} placeholder="https://api.openai.com/v1" mono />
                </div>
              </div>
              <div className="flex items-center gap-2">
                <Badge variant="warning">Required</Badge>
                <span className="text-xs text-text-muted">An LLM provider is needed for harness generation.</span>
              </div>
            </div>
          )}

          {step === "runtime" && (
            <div className="flex flex-col gap-3">
              <h2 className="text-sm font-semibold">Sandbox Configuration</h2>
              <p className="text-xs text-text-secondary">All harness builds and fuzz runs execute in a Docker sandbox for safety.</p>
              <div className="flex items-center justify-between p-3 rounded-md" style={{ background: "var(--surface-code)", border: "1px solid var(--border)" }}>
                <div>
                  <span className="text-xs text-text-primary">Use Docker sandbox</span>
                  <p className="text-xs text-text-muted mt-0.5">Recommended: isolates untrusted harness execution.</p>
                </div>
                <Switch checked={useDocker} onChange={setUseDocker} />
              </div>
              {useDocker && (
                <div className="text-xs text-text-muted p-3 rounded-md" style={{ background: "var(--surface-code)", border: "1px solid var(--border)" }}>
                  Build the sandbox image with: <code style={{ color: "var(--accent)" }}>./scripts/build-sandbox.sh</code>
                </div>
              )}
            </div>
          )}

          {step === "guardrails" && (
            <div className="flex flex-col gap-3">
              <h2 className="text-sm font-semibold">Safety Guardrails</h2>
              <p className="text-xs text-text-secondary">Human-in-the-loop approval gates for safety-first fuzzing.</p>
              <div className="flex items-center justify-between p-3 rounded-md" style={{ background: "var(--surface-code)", border: "1px solid var(--border)" }}>
                <div>
                  <span className="text-xs text-text-primary">Approve harness compilation</span>
                  <p className="text-xs text-text-muted mt-0.5">Review generated harness source before compiling.</p>
                </div>
                <Switch checked={requireHarnessApproval} onChange={setRequireHarnessApproval} />
              </div>
              <div className="flex items-center justify-between p-3 rounded-md" style={{ background: "var(--surface-code)", border: "1px solid var(--border)" }}>
                <div>
                  <span className="text-xs text-text-primary">Approve fuzzer execution</span>
                  <p className="text-xs text-text-muted mt-0.5">Confirm before starting a fuzz run.</p>
                </div>
                <Switch checked={requireRunApproval} onChange={setRequireRunApproval} />
              </div>
            </div>
          )}

          {step === "storage" && (
            <div className="flex flex-col gap-3">
              <h2 className="text-sm font-semibold">Storage</h2>
              <p className="text-xs text-text-secondary">Where to store run data, corpora, and crash artifacts.</p>
              <div className="text-xs text-text-muted p-3 rounded-md" style={{ background: "var(--surface-code)", border: "1px solid var(--border)" }}>
                <div className="flex justify-between mb-1"><span>Database:</span><code style={{ color: "var(--accent)" }}>data/hobot_fuzz.db</code></div>
                <div className="flex justify-between mb-1"><span>Transcripts:</span><code style={{ color: "var(--accent)" }}>data/transcripts/</code></div>
                <div className="flex justify-between"><span>Workspace:</span><code style={{ color: "var(--accent)" }}>/tmp/hobot_fuzz_workspace/</code></div>
              </div>
            </div>
          )}

          {step === "complete" && (
            <div className="flex flex-col gap-3 items-center text-center" style={{ padding: "var(--space-lg) 0" }}>
              <div className="flex items-center justify-center rounded-full" style={{ width: "56px", height: "56px", background: "rgba(111,207,151,0.15)", border: "1px solid var(--success)" }}>
                <CheckCircle2 size={28} style={{ color: "var(--success)" }} />
              </div>
              <h2 className="text-sm font-semibold">Setup Complete!</h2>
              <p className="text-xs text-text-secondary max-w-xs">
                hobot_fuzz is ready. Start by discovering targets in a project, or ask the AI assistant for help.
              </p>
            </div>
          )}
        </div>

        {/* Navigation */}
        <Separator />
        <div className="flex items-center justify-between pt-3">
          <Button variant="ghost" size="sm" onClick={prev} disabled={stepIdx === 0}>
            <ArrowLeft size={14} /> Back
          </Button>
          <div className="flex gap-2">
            {stepIdx < STEPS.length - 1 && step !== "welcome" && (
              <Button variant="ghost" size="sm" onClick={onComplete}>Skip</Button>
            )}
            {stepIdx < STEPS.length - 1 ? (
              <Button variant="primary" size="sm" onClick={next}>
                Next <ArrowRight size={14} />
              </Button>
            ) : (
              <Button variant="primary" size="sm" onClick={finish} disabled={saving}>
                {saving ? "Saving…" : "Get Started"} <CheckCircle2 size={14} />
              </Button>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}