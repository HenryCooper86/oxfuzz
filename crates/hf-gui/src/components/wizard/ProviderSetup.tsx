import { useEffect, useRef, useState } from "react";
import { getTransport } from "../../lib";
import { useI18n } from "../../i18nContext";
import { Button } from "../ui/Button";
import { Input } from "../ui/Input";
import { Select } from "../ui/Select";
import type { Provider } from "../settings/providerTypes";
import { resolveWizardProvider, wizardProviderPreset, WIZARD_PROVIDER_TYPES, type WizardProviderInput } from "./wizardProvider";

export function ProviderSetup({ onContinue }: { onContinue: () => void }) {
  const { t } = useI18n();
  const [providers, setProviders] = useState<Provider[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [attempt, setAttempt] = useState(0);
  useEffect(() => {
    let active = true;
    void getTransport().invoke<Provider[]>("setup_providers").then(value => {
      if (!Array.isArray(value)) throw new Error(t("setup.invalidResponse"));
      if (active) setProviders(value);
    }).catch((error: unknown) => { if (active) setError(String(error)); });
    return () => { active = false; };
  }, [attempt, t]);
  if (error) return <div role="alert"><p>{t("setup.providerLoadFailed")}: {error}</p><Button onClick={() => { setError(null); setAttempt(value => value + 1); }}>{t("setup.checkAgain")}</Button></div>;
  if (providers === null) return <p role="status">{t("setup.loadingProviders")}</p>;
  if (providers.length > 0) return <div className="flex flex-col gap-3">
    <p className="m-0">{t("setup.savedProviders")}</p>
    <ul className="m-0 pl-5">{providers.map(provider => <li key={provider.id}>{provider.id} · {provider.model}</li>)}</ul>
    <p className="m-0 text-sm text-text-secondary">{t("setup.keepProviders")}</p>
    {!providers.some(provider => provider.enabled) && <p role="alert">{t("setup.providersDisabled")}</p>}
    <Button variant="primary" disabled={!providers.some(provider => provider.enabled)} onClick={onContinue}>{t("setup.continue")}</Button>
  </div>;
  return <NewProviderSetup onContinue={onContinue} />;
}

function NewProviderSetup({ onContinue }: { onContinue: () => void }) {
  const { t } = useI18n();
  const preset = wizardProviderPreset("openai");
  const [input, setInput] = useState<WizardProviderInput>({ providerType: "openai", apiKey: "", model: preset.model, baseUrl: preset.baseUrl });
  const [probe, setProbe] = useState<"idle" | "testing" | "passed">("idle");
  const [error, setError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);
  const revision = useRef(0);
  const active = useRef(true);
  const writing = useRef(false);
  useEffect(() => { active.current = true; return () => { active.current = false; }; }, []);
  const keyOptional = wizardProviderPreset(input.providerType).keyOptional;
  const canTest = input.model.trim() !== "" && input.baseUrl.trim() !== "" && (keyOptional || input.apiKey.trim() !== "");
  function update(patch: Partial<WizardProviderInput>) {
    revision.current++;
    setInput(value => ({ ...value, ...patch }));
    setProbe("idle"); setError(null);
  }
  async function test() {
    const provider = resolveWizardProvider(input);
    if (!provider || !canTest) return;
    const current = ++revision.current;
    setProbe("testing"); setError(null);
    try {
      await getTransport().invoke<string>("provider_test", { provider });
      if (active.current && current === revision.current) setProbe("passed");
    } catch (error) {
      if (active.current && current === revision.current) { setProbe("idle"); setError(String(error)); }
    }
  }
  async function save() {
    const provider = resolveWizardProvider(input);
    if (probe !== "passed" || !provider || writing.current) return;
    writing.current = true; setSaving(true); setError(null);
    try {
      await getTransport().invoke("initialize_provider", { provider });
      if (active.current) { localStorage.setItem("hf_provider_model", provider.model); onContinue(); }
    } catch (error) { if (active.current) setError(String(error)); }
    finally { writing.current = false; if (active.current) setSaving(false); }
  }
  return <div className="flex flex-col gap-4">
    <p className="m-0 text-sm text-text-secondary">{t("setup.providerHint")}</p>
    <div><label htmlFor="setup-provider" className="block text-sm mb-1">{t("setup.provider")}</label>
      <Select id="setup-provider" value={input.providerType} disabled={saving} options={WIZARD_PROVIDER_TYPES} className="w-full" onChange={providerType => { const preset = wizardProviderPreset(providerType); update({ providerType, apiKey: "", model: preset.model, baseUrl: preset.baseUrl }); }} />
    </div>
    <div><label htmlFor="setup-key" className="block text-sm mb-1">{t("setup.apiKey")}{keyOptional ? ` (${t("setup.optional")})` : ""}</label>
      <Input id="setup-key" type="password" autoComplete="off" disabled={saving} value={input.apiKey} onChange={event => update({ apiKey: event.target.value })} />
    </div>
    <div><label htmlFor="setup-model" className="block text-sm mb-1">{t("setup.model")}</label>
      <Input id="setup-model" aria-describedby="setup-model-hint" disabled={saving} value={input.model} onChange={event => update({ model: event.target.value })} />
      <p id="setup-model-hint" className="mt-1 mb-0 text-sm text-text-secondary">{t("setup.modelHint")}</p>
    </div>
    <details open={input.providerType === "openai-compat" ? true : undefined}>
      <summary className="cursor-pointer text-sm">{t("setup.advanced")}</summary>
      <label htmlFor="setup-url" className="block text-sm mt-2 mb-1">{t("setup.baseUrl")}</label>
      <Input id="setup-url" type="url" disabled={saving} value={input.baseUrl} onChange={event => update({ baseUrl: event.target.value })} />
    </details>
    <p className="m-0 text-sm text-text-secondary">{t("setup.probeNotice")}</p>
    {error && <p role="alert" className="m-0 text-sm break-words">{t("setup.connectionFailed")}: {error}</p>}
    {probe === "passed" && <p role="status" className="m-0 text-sm">{t("setup.connectionVerified")}</p>}
    <div className="flex flex-wrap gap-2">
      <Button variant="outline" disabled={!canTest || probe === "testing" || saving} onClick={() => void test()}>{t(probe === "testing" ? "setup.testing" : "setup.testConnection")}</Button>
      <Button variant="primary" disabled={probe !== "passed" || saving} onClick={() => void save()}>{t(saving ? "setup.saving" : "setup.saveContinue")}</Button>
    </div>
  </div>;
}
