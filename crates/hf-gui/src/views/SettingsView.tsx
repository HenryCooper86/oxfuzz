import { useState } from "react";

export function SettingsView() {
  const [apiKey, setApiKey] = useState("");
  const [model, setModel] = useState("gpt-4o");
  const [baseUrl, setBaseUrl] = useState("https://api.openai.com/v1");
  const [saved, setSaved] = useState(false);

  function save() {
    localStorage.setItem("hf_provider_api_key", apiKey);
    localStorage.setItem("hf_provider_model", model);
    localStorage.setItem("hf_provider_base_url", baseUrl);
    setSaved(true);
    setTimeout(() => setSaved(false), 2000);
  }

  return (
    <div className="flex flex-col gap-4 max-w-lg">
      <h1 className="text-xl font-bold">Settings</h1>
      <div className="flex flex-col gap-2">
        <label className="text-sm text-text-secondary">API Key</label>
        <input
          type="password"
          value={apiKey}
          onChange={(e) => setApiKey(e.target.value)}
          className="px-3 py-2 bg-surface-secondary border border-border rounded-DEFAULT text-text-primary"
        />
        <label className="text-sm text-text-secondary">Model</label>
        <input
          type="text"
          value={model}
          onChange={(e) => setModel(e.target.value)}
          className="px-3 py-2 bg-surface-secondary border border-border rounded-DEFAULT text-text-primary"
        />
        <label className="text-sm text-text-secondary">Base URL</label>
        <input
          type="text"
          value={baseUrl}
          onChange={(e) => setBaseUrl(e.target.value)}
          className="px-3 py-2 bg-surface-secondary border border-border rounded-DEFAULT text-text-primary"
        />
        <button
          onClick={save}
          className="self-start px-4 py-2 bg-accent text-surface-tertiary rounded-DEFAULT hover:bg-accent-hover mt-2"
        >
          Save
        </button>
        {saved && <p className="text-success text-sm">Saved.</p>}
      </div>
    </div>
  );
}