import { useState } from "react";
import { Check } from "lucide-react";

export function SettingsView() {
  const [apiKey, setApiKey] = useState(localStorage.getItem("hf_provider_api_key") || "");
  const [model, setModel] = useState(localStorage.getItem("hf_provider_model") || "gpt-4o");
  const [baseUrl, setBaseUrl] = useState(localStorage.getItem("hf_provider_base_url") || "https://api.openai.com/v1");
  const [saved, setSaved] = useState(false);

  function save() {
    localStorage.setItem("hf_provider_api_key", apiKey);
    localStorage.setItem("hf_provider_model", model);
    localStorage.setItem("hf_provider_base_url", baseUrl);
    setSaved(true);
    setTimeout(() => setSaved(false), 2000);
  }

  return (
    <div className="flex flex-col gap-4 max-w-lg" style={{ animation: "fadeIn 0.2s ease" }}>
      <h1 className="text-xl font-semibold">Settings</h1>
      <p className="text-sm text-text-secondary">Configure the LLM provider for harness generation and crash triage.</p>

      <div className="flex flex-col gap-4">
        <SettingField label="API Key" type="password" value={apiKey} onChange={setApiKey} placeholder="sk-..." />
        <SettingField label="Model" value={model} onChange={setModel} placeholder="gpt-4o" />
        <SettingField label="Base URL" value={baseUrl} onChange={setBaseUrl} placeholder="https://api.openai.com/v1" mono />
      </div>

      <button
        onClick={save}
        className="self-start inline-flex items-center justify-center gap-1 px-4 py-2 text-xs font-medium rounded-md border border-solid transition-all duration-150 outline-none"
        style={{
          background: "var(--accent)",
          color: "var(--accent-contrast)",
          borderColor: "transparent",
        }}
        onMouseEnter={(e) => (e.currentTarget.style.opacity = "0.85")}
        onMouseLeave={(e) => (e.currentTarget.style.opacity = "1")}
      >
        <Check size={14} />
        Save Settings
      </button>

      {saved && (
        <div
          className="rounded-md text-xs px-3 py-2"
          style={{ background: "rgba(111,207,151,0.1)", color: "var(--success)", animation: "fadeIn 0.2s ease" }}
        >
          Settings saved.
        </div>
      )}
    </div>
  );
}

function SettingField({
  label,
  value,
  onChange,
  placeholder,
  type = "text",
  mono = false,
}: {
  label: string;
  value: string;
  onChange: (v: string) => void;
  placeholder?: string;
  type?: string;
  mono?: boolean;
}) {
  return (
    <div className="flex flex-col gap-1">
      <label className="text-xs text-text-muted uppercase" style={{ fontWeight: 600, letterSpacing: "0.05em" }}>
        {label}
      </label>
      <input
        type={type}
        value={value}
        onChange={(e) => onChange(e.target.value)}
        placeholder={placeholder}
        className="px-3 py-2 text-xs border border-solid border-border rounded-md bg-surface-primary text-text-primary outline-none focus:border-[var(--border-focus)] transition-colors duration-150"
        style={{ fontFamily: mono ? "var(--font-mono)" : "var(--font-sans)" }}
      />
    </div>
  );
}