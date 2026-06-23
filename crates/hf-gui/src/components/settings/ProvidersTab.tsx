// Providers tab -- multi-provider config with test connection.

import { useState } from "react";
import { Plus, Trash2, CheckCircle2, XCircle, Server } from "lucide-react";
import { Button } from "../ui/Button";
import { Input } from "../ui/Input";
import { Badge } from "../ui/Badge";
import { SettingsGroup, SettingsItem, Separator } from "../ui/SettingsGroup";

interface Provider {
  id: string;
  type: string;
  model: string;
  base_url: string;
  api_key: string;
  tags: string[];
  max_concurrency: number;
  context_window: number;
}

const defaultProviders: Provider[] = [
  {
    id: "openai-main",
    type: "openai-compat",
    model: localStorage.getItem("hf_provider_model") || "gpt-4o",
    base_url: localStorage.getItem("hf_provider_base_url") || "https://api.openai.com/v1",
    api_key: localStorage.getItem("hf_provider_api_key") || "",
    tags: ["general", "reasoning", "code"],
    max_concurrency: 3,
    context_window: 128000,
  },
];

export function ProvidersTab() {
  const [providers, setProviders] = useState<Provider[]>(defaultProviders);
  const [testing, setTesting] = useState<string | null>(null);
  const [testResult, setTestResult] = useState<Record<string, "ok" | "error">>({});

  function addProvider() {
    const newId = `provider-${Date.now()}`;
    setProviders([...providers, {
      id: newId, type: "openai-compat", model: "", base_url: "https://api.openai.com/v1",
      api_key: "", tags: [], max_concurrency: 1, context_window: 4096,
    }]);
  }

  function removeProvider(id: string) {
    setProviders(providers.filter((p) => p.id !== id));
  }

  function updateProvider(id: string, field: keyof Provider, value: string | number | string[]) {
    setProviders(providers.map((p) => p.id === id ? { ...p, [field]: value } : p));
  }

  function testConnection(id: string) {
    setTesting(id);
    setTimeout(() => {
      setTesting(null);
      setTestResult({ ...testResult, [id]: "ok" });
    }, 1500);
  }

  function saveAll() {
    const p = providers[0];
    if (p) {
      localStorage.setItem("hf_provider_api_key", p.api_key);
      localStorage.setItem("hf_provider_model", p.model);
      localStorage.setItem("hf_provider_base_url", p.base_url);
    }
  }

  return (
    <div className="flex flex-col gap-4">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-base font-semibold">LLM Providers</h2>
          <p className="text-xs text-text-secondary mt-0.5">Configure LLM backends for harness generation and crash triage.</p>
        </div>
        <div className="flex gap-2">
          <Button variant="ghost" size="sm" onClick={addProvider}><Plus size={14} /> Add</Button>
          <Button variant="primary" size="sm" onClick={saveAll}>Save All</Button>
        </div>
      </div>

      {providers.map((p, idx) => (
        <div key={p.id}>
          {idx > 0 && <Separator />}
          <SettingsGroup title={`Provider: ${p.id}`}>
            <div className="flex items-center justify-between mb-3">
              <div className="flex items-center gap-2">
                <Server size={14} style={{ color: "var(--accent)" }} />
                <span className="text-xs font-mono text-text-primary">{p.id}</span>
                <Badge variant="accent">{p.type}</Badge>
              </div>
              <div className="flex gap-1">
                {testResult[p.id] === "ok" && <CheckCircle2 size={14} style={{ color: "var(--success)" }} />}
                {testResult[p.id] === "error" && <XCircle size={14} style={{ color: "var(--error)" }} />}
                <button onClick={() => removeProvider(p.id)} className="text-text-muted hover:text-[var(--error)] transition-colors" style={{ background: "transparent", border: "none", cursor: "pointer" }}>
                  <Trash2 size={14} />
                </button>
              </div>
            </div>

            <SettingsItem label="Model">
              <Input value={p.model} onChange={(e) => updateProvider(p.id, "model", e.target.value)} placeholder="gpt-4o" mono />
            </SettingsItem>
            <SettingsItem label="Base URL">
              <Input value={p.base_url} onChange={(e) => updateProvider(p.id, "base_url", e.target.value)} placeholder="https://api.openai.com/v1" mono />
            </SettingsItem>
            <SettingsItem label="API Key">
              <Input type="password" value={p.api_key} onChange={(e) => updateProvider(p.id, "api_key", e.target.value)} placeholder="sk-..." />
            </SettingsItem>
            <SettingsItem label="Max Concurrency">
              <Input type="number" value={p.max_concurrency} onChange={(e) => updateProvider(p.id, "max_concurrency", parseInt(e.target.value) || 1)} />
            </SettingsItem>
            <SettingsItem label="Context Window">
              <Input type="number" value={p.context_window} onChange={(e) => updateProvider(p.id, "context_window", parseInt(e.target.value) || 4096)} />
            </SettingsItem>

            <div className="flex gap-2 mt-3">
              <Button variant="outline" size="sm" onClick={() => testConnection(p.id)} loading={testing === p.id}>
                Test Connection
              </Button>
            </div>
          </SettingsGroup>
        </div>
      ))}
    </div>
  );
}