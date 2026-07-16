// Setup Wizard -- first-run onboarding for safety-first fuzzing.
// Modeled after y-agent's SetupWizard with 6 steps.

import { useEffect, useState, type ReactNode } from "react";
import { Crosshair, Server, Shield, Database, CheckCircle2, ArrowRight, ArrowLeft } from "lucide-react";
import { Button } from "../ui/Button";
import { Input } from "../ui/Input";
import { Badge } from "../ui/Badge";
import { Separator } from "../ui/Separator";
import { useToast } from "../ui/toastContext";
import { getTransport } from "../../lib";
import { useI18n } from "../../i18nContext";
import { normalizeProvider, type Provider } from "../settings/providerTypes";
import { wizardStoragePaths, type WizardStoragePaths } from "../../lib/wizardPaths";

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
  const { t } = useI18n();
  const { toast } = useToast();
  const [step, setStep] = useState<Step>("welcome");
  const [saving, setSaving] = useState(false);
  const [storagePaths, setStoragePaths] = useState<WizardStoragePaths>({
    database: "--",
    transcripts: "--",
    workspace: "--",
  });
  const stepIdx = STEPS.findIndex((s) => s.id === step);

  // Config state
  const [apiKey, setApiKey] = useState("");
  const [model, setModel] = useState("gpt-4o");
  const [baseUrl, setBaseUrl] = useState("https://api.openai.com/v1");

  useEffect(() => {
    getTransport()
      .invoke<{ data_dir: string; workspace_dir: string }>("app_paths")
      .then((paths) => setStoragePaths(wizardStoragePaths(paths)))
      .catch(() => {
        // Keep neutral placeholders when the service cannot resolve its paths.
      });
  }, []);

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
      toast({ title: t("wizard.saveFailed"), description: String(e), variant: "error" });
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
            <h1 className="text-base font-semibold">{t("wizard.title")}</h1>
            <p className="text-xs text-text-secondary">{t("wizard.subtitle")}</p>
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
              <h2 className="text-sm font-semibold">{t("welcome.title")}</h2>
              <p className="text-xs text-text-secondary leading-relaxed">
                {t("wizard.welcomeP1")}
              </p>
              <p className="text-xs text-text-secondary leading-relaxed">
                {t("wizard.welcomeP2")}
              </p>
              <Separator />
              <div className="flex flex-col gap-1 text-xs text-text-muted">
                <span className="flex items-center gap-2"><Crosshair size={12} style={{ color: "var(--accent)" }} /> {t("wizard.feat1")}</span>
                <span className="flex items-center gap-2"><Crosshair size={12} style={{ color: "var(--accent)" }} /> {t("wizard.feat2")}</span>
                <span className="flex items-center gap-2"><Crosshair size={12} style={{ color: "var(--accent)" }} /> {t("wizard.feat3")}</span>
                <span className="flex items-center gap-2"><Crosshair size={12} style={{ color: "var(--accent)" }} /> {t("wizard.feat4")}</span>
              </div>
            </div>
          )}

          {step === "providers" && (
            <div className="flex flex-col gap-3">
              <h2 className="text-sm font-semibold">{t("wizard.providerTitle")}</h2>
              <p className="text-xs text-text-secondary">{t("wizard.providerDesc")}</p>
              <div className="flex flex-col gap-2">
                <div>
                  <label className="text-xs text-text-muted uppercase mb-1 block" style={{ fontWeight: 600, letterSpacing: "0.05em" }}>{t("wizard.apiKey")}</label>
                  <Input type="password" value={apiKey} onChange={(e) => setApiKey(e.target.value)} placeholder="sk-..." />
                </div>
                <div>
                  <label className="text-xs text-text-muted uppercase mb-1 block" style={{ fontWeight: 600, letterSpacing: "0.05em" }}>{t("wizard.model")}</label>
                  <Input value={model} onChange={(e) => setModel(e.target.value)} placeholder="gpt-4o" mono />
                </div>
                <div>
                  <label className="text-xs text-text-muted uppercase mb-1 block" style={{ fontWeight: 600, letterSpacing: "0.05em" }}>{t("wizard.baseUrl")}</label>
                  <Input value={baseUrl} onChange={(e) => setBaseUrl(e.target.value)} placeholder="https://api.openai.com/v1" mono />
                </div>
              </div>
              <div className="flex items-center gap-2">
                <Badge variant="warning">{t("wizard.required")}</Badge>
                <span className="text-xs text-text-muted">{t("wizard.providerRequired")}</span>
              </div>
            </div>
          )}

          {step === "runtime" && (
            <div className="flex flex-col gap-3">
              <h2 className="text-sm font-semibold">{t("wizard.sandboxTitle")}</h2>
              <p className="text-xs text-text-secondary">{t("wizard.sandboxDesc")}</p>
              <div className="flex items-center justify-between p-3 rounded-md" style={{ background: "var(--surface-code)", border: "1px solid var(--border)" }}>
                <div>
                  <span className="text-xs text-text-primary">{t("settings.fuzzing.sandboxRequired")}</span>
                  <p className="text-xs text-text-muted mt-0.5">{t("settings.fuzzing.protectionsDesc")}</p>
                </div>
                <Badge variant="success">{t("settings.fuzzing.alwaysOn")}</Badge>
              </div>
              <div className="text-xs text-text-muted p-3 rounded-md" style={{ background: "var(--surface-code)", border: "1px solid var(--border)" }}>
                {t("wizard.buildImage")} <code style={{ color: "var(--accent)" }}>./scripts/build-sandbox.sh</code>
              </div>
            </div>
          )}

          {step === "guardrails" && (
            <div className="flex flex-col gap-3">
              <h2 className="text-sm font-semibold">{t("wizard.guardrailsTitle")}</h2>
              <p className="text-xs text-text-secondary">{t("wizard.guardrailsDesc")}</p>
              <div className="flex items-center justify-between p-3 rounded-md" style={{ background: "var(--surface-code)", border: "1px solid var(--border)" }}>
                <div>
                  <span className="text-xs text-text-primary">{t("wizard.approveHarness")}</span>
                  <p className="text-xs text-text-muted mt-0.5">{t("wizard.approveHarnessDesc")}</p>
                </div>
                <Badge variant="success">{t("settings.fuzzing.required")}</Badge>
              </div>
              <div className="flex items-center justify-between p-3 rounded-md" style={{ background: "var(--surface-code)", border: "1px solid var(--border)" }}>
                <div>
                  <span className="text-xs text-text-primary">{t("wizard.approveRun")}</span>
                  <p className="text-xs text-text-muted mt-0.5">{t("wizard.approveRunDesc")}</p>
                </div>
                <Badge variant="success">{t("settings.fuzzing.required")}</Badge>
              </div>
            </div>
          )}

          {step === "storage" && (
            <div className="flex flex-col gap-3">
              <h2 className="text-sm font-semibold">{t("wizard.storageTitle")}</h2>
              <p className="text-xs text-text-secondary">{t("wizard.storageDesc")}</p>
              <div className="text-xs text-text-muted p-3 rounded-md" style={{ background: "var(--surface-code)", border: "1px solid var(--border)" }}>
                <div className="flex justify-between mb-1"><span>{t("wizard.dbLabel")}</span><code style={{ color: "var(--accent)" }}>{storagePaths.database}</code></div>
                <div className="flex justify-between mb-1"><span>{t("wizard.transcriptsLabel")}</span><code style={{ color: "var(--accent)" }}>{storagePaths.transcripts}</code></div>
                <div className="flex justify-between"><span>{t("wizard.workspaceLabel")}</span><code style={{ color: "var(--accent)" }}>{storagePaths.workspace}</code></div>
              </div>
            </div>
          )}

          {step === "complete" && (
            <div className="flex flex-col gap-3 items-center text-center" style={{ padding: "var(--space-lg) 0" }}>
              <div className="flex items-center justify-center rounded-full" style={{ width: "56px", height: "56px", background: "rgba(111,207,151,0.15)", border: "1px solid var(--success)" }}>
                <CheckCircle2 size={28} style={{ color: "var(--success)" }} />
              </div>
              <h2 className="text-sm font-semibold">{t("wizard.completeTitle")}</h2>
              <p className="text-xs text-text-secondary max-w-xs">
                {t("wizard.completeDesc")}
              </p>
            </div>
          )}
        </div>

        {/* Navigation */}
        <Separator />
        <div className="flex items-center justify-between pt-3">
          <Button variant="ghost" size="sm" onClick={prev} disabled={stepIdx === 0}>
            <ArrowLeft size={14} /> {t("common.back")}
          </Button>
          <div className="flex gap-2">
            {stepIdx < STEPS.length - 1 && step !== "welcome" && (
              <Button variant="ghost" size="sm" onClick={onComplete}>{t("wizard.skip")}</Button>
            )}
            {stepIdx < STEPS.length - 1 ? (
              <Button variant="primary" size="sm" onClick={next}>
                {t("common.next")} <ArrowRight size={14} />
              </Button>
            ) : (
              <Button variant="primary" size="sm" onClick={finish} disabled={saving}>
                {saving ? t("wizard.saving") : t("wizard.getStarted")} <CheckCircle2 size={14} />
              </Button>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
