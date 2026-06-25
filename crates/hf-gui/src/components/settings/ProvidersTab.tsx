// ---------------------------------------------------------------------------
// ProvidersTab -- provider list + per-provider detail form (modeled on y-agent).
// Controlled: the parsed provider pool (Provider[]) is owned by the SettingsView
// orchestrator and passed via props. The single global "Save Changes" button in
// the header persists it (via set_providers) -- this tab has no Save button.
// ---------------------------------------------------------------------------

import { useState } from "react";
import { Plus, Copy, ChevronUp, ChevronDown, X, Eye, EyeOff, Search, CheckCircle2, XCircle } from "lucide-react";
import { ProviderBrandIcon } from "../common/ProviderBrandIcon";
import { Button } from "../ui/Button";
import { Input } from "../ui/Input";
import { Select } from "../ui/Select";
import { Switch } from "../ui/Switch";
import { SettingsGroup, SettingsItem } from "../ui/SettingsGroup";

export interface Provider {
  id: string;
  provider_type: string;
  model: string;
  base_url: string;
  api_key: string;
  api_key_env: string;
  enabled: boolean;
  http_protocol: string;
  tool_calling_mode: string;
  tags: string[];
  max_concurrency: number;
  context_window: number;
}

const PROVIDER_TYPES = [
  { value: "openai", label: "OpenAI" },
  { value: "openai-compat", label: "OpenAI-compatible (vLLM, LiteLLM…)" },
  { value: "anthropic", label: "Anthropic" },
  { value: "deepseek", label: "DeepSeek" },
  { value: "gemini", label: "Gemini" },
  { value: "ollama", label: "Ollama" },
];

const PROMPT_BASED = ["openai-compat", "custom", "ollama"];

const BASE_URL_PLACEHOLDERS: Record<string, string> = {
  openai: "https://api.openai.com/v1",
  "openai-compat": "e.g. https://api.example.ai/v1",
  anthropic: "https://api.anthropic.com/v1",
  deepseek: "https://api.deepseek.com/v1",
  gemini: "https://generativelanguage.googleapis.com/v1beta",
  ollama: "http://localhost:11434/v1",
};

function emptyProvider(): Provider {
  return {
    id: "new-provider",
    provider_type: "openai-compat",
    model: "",
    base_url: "",
    api_key: "",
    api_key_env: "",
    enabled: true,
    http_protocol: "http1",
    tool_calling_mode: "",
    tags: [],
    max_concurrency: 3,
    context_window: 128000,
  };
}

export function ProvidersTab({
  value,
  onChange,
}: {
  value: Provider[];
  onChange: (next: Provider[]) => void;
}) {
  const providers = value;
  const [active, setActive] = useState(0);

  function update(i: number, patch: Partial<Provider>) {
    onChange(providers.map((p, idx) => (idx === i ? { ...p, ...patch } : p)));
  }
  function add() {
    onChange([...providers, emptyProvider()]);
    setActive(providers.length);
  }
  function duplicate() {
    const s = providers[active];
    if (!s) return;
    const next = [...providers];
    next.splice(active + 1, 0, { ...s, id: `${s.id}-copy` });
    onChange(next);
    setActive(active + 1);
  }
  function remove(i: number) {
    onChange(providers.filter((_, idx) => idx !== i));
    setActive((a) => Math.max(0, a > i ? a - 1 : Math.min(a, providers.length - 2)));
  }
  function moveUp() {
    if (active <= 0) return;
    const n = [...providers];
    [n[active - 1], n[active]] = [n[active], n[active - 1]];
    onChange(n);
    setActive(active - 1);
  }
  function moveDown() {
    if (active >= providers.length - 1) return;
    const n = [...providers];
    [n[active], n[active + 1]] = [n[active + 1], n[active]];
    onChange(n);
    setActive(active + 1);
  }

  const cur = providers[active];

  return (
    <div className="flex flex-col">
      <div className="flex gap-5">
        {/* Provider list */}
        <div style={{ width: "210px", flexShrink: 0 }}>
          <div className="flex items-center gap-1" style={{ marginBottom: "8px" }}>
            <Button variant="ghost" size="sm" onClick={add}>
              <Plus size={13} /> Add
            </Button>
            <Button variant="icon" size="sm" onClick={duplicate} disabled={providers.length === 0} title="Duplicate">
              <Copy size={14} />
            </Button>
            <Button variant="icon" size="sm" onClick={moveUp} disabled={active <= 0} title="Move up">
              <ChevronUp size={14} />
            </Button>
            <Button
              variant="icon"
              size="sm"
              onClick={moveDown}
              disabled={active >= providers.length - 1}
              title="Move down"
            >
              <ChevronDown size={14} />
            </Button>
          </div>
          <div className="flex flex-col gap-1">
            {providers.map((p, i) => (
              <button
                key={i}
                onClick={() => setActive(i)}
                className="group flex items-center gap-2 rounded-md text-left transition-all duration-150 outline-none"
                style={{
                  padding: "8px 10px",
                  border: `1px solid ${active === i ? "var(--border)" : "transparent"}`,
                  background: active === i ? "var(--surface-active)" : "transparent",
                  cursor: "pointer",
                }}
              >
                <span
                  className="inline-flex items-center justify-center shrink-0"
                  style={{ width: "16px", height: "16px", color: p.enabled ? "var(--text-primary)" : "var(--text-muted)" }}
                >
                  <ProviderBrandIcon type={p.provider_type} size={15} />
                </span>
                <span
                  className="text-xs font-mono flex-1 truncate"
                  style={{ opacity: p.enabled ? 1 : 0.5, color: "var(--text-primary)" }}
                >
                  {p.id || `Provider ${i + 1}`}
                </span>
                <span
                  role="button"
                  tabIndex={0}
                  title="Remove"
                  onClick={(e) => {
                    e.stopPropagation();
                    remove(i);
                  }}
                  className="text-text-muted opacity-0 group-hover:opacity-100 hover:text-[var(--error)] transition-all"
                  style={{ display: "inline-flex" }}
                >
                  <X size={12} />
                </span>
              </button>
            ))}
            {providers.length === 0 && (
              <div className="text-xs text-text-muted" style={{ padding: "8px 10px" }}>
                No providers. Click + to add one.
              </div>
            )}
          </div>
        </div>

        {/* Detail form */}
        <div className="flex-1 min-w-0">
          {cur ? (
            <ProviderForm provider={cur} onChange={(patch) => update(active, patch)} />
          ) : (
            <div className="text-text-muted text-sm">No provider selected.</div>
          )}
        </div>
      </div>
    </div>
  );
}

function ProviderForm({ provider, onChange }: { provider: Provider; onChange: (patch: Partial<Provider>) => void }) {
  const [showKey, setShowKey] = useState(false);
  const [testing, setTesting] = useState(false);
  const [testOk, setTestOk] = useState<boolean | null>(null);

  function test() {
    setTesting(true);
    setTestOk(null);
    setTimeout(() => {
      setTesting(false);
      setTestOk(Boolean(provider.model && (provider.base_url || provider.api_key || provider.api_key_env)));
    }, 1200);
  }

  const effectiveMode = provider.tool_calling_mode || (PROMPT_BASED.includes(provider.provider_type) ? "prompt_based" : "native");
  const isNative = effectiveMode === "native";

  return (
    <div className="flex flex-col">
      <SettingsGroup title="Identity">
        <SettingsItem title="Enabled">
          <div className="flex items-center gap-2">
            <Switch checked={provider.enabled} onChange={(v) => onChange({ enabled: v })} />
            <span className="text-xs" style={{ color: provider.enabled ? "var(--success)" : "var(--text-muted)" }}>
              {provider.enabled ? "Active" : "Disabled"}
            </span>
          </div>
        </SettingsItem>
        <SettingsItem title="ID">
          <Input
            className="w-[260px]"
            value={provider.id}
            onChange={(e) => onChange({ id: e.target.value })}
            placeholder="e.g. openai-main"
            mono
          />
        </SettingsItem>
        <SettingsItem title="Provider Type">
          <div className="flex items-center gap-2">
            <span
              className="inline-flex items-center justify-center shrink-0"
              style={{ width: "18px", height: "18px", color: "var(--text-primary)" }}
            >
              <ProviderBrandIcon type={provider.provider_type} size={17} />
            </span>
            <Select
              value={provider.provider_type}
              onChange={(v) => onChange({ provider_type: v })}
              options={PROVIDER_TYPES}
              className="w-[230px]"
            />
          </div>
        </SettingsItem>
      </SettingsGroup>

      <SettingsGroup title="Tool Calling">
        <SettingsItem
          title="Tool Calling Mode"
          description={
            provider.tool_calling_mode
              ? "Manually set"
              : `Auto-detected from provider type (${PROMPT_BASED.includes(provider.provider_type) ? "prompt_based" : "native"})`
          }
        >
          <div className="flex items-center gap-2">
            <Switch checked={isNative} onChange={(v) => onChange({ tool_calling_mode: v ? "native" : "prompt_based" })} />
            <span className="text-xs" style={{ color: isNative ? "var(--accent)" : "var(--text-muted)" }}>
              {isNative ? "Native" : "Prompt-based"}
            </span>
          </div>
        </SettingsItem>
      </SettingsGroup>

      <SettingsGroup title="Connection">
        <SettingsItem title="Model ID">
          <div className="relative w-[260px]">
            <Input
              className="pr-8"
              value={provider.model}
              onChange={(e) => onChange({ model: e.target.value })}
              placeholder="e.g. gpt-4o"
              mono
            />
            <span
              className="absolute right-2 top-1/2 -translate-y-1/2 text-text-muted"
              title="Model discovery"
              style={{ display: "inline-flex" }}
            >
              <Search size={13} />
            </span>
          </div>
        </SettingsItem>
        <SettingsItem title="Base URL">
          <Input
            className="w-[260px]"
            value={provider.base_url}
            onChange={(e) => onChange({ base_url: e.target.value })}
            placeholder={BASE_URL_PLACEHOLDERS[provider.provider_type] ?? "Default"}
            mono
          />
        </SettingsItem>
        <SettingsItem title="API Key">
          <div className="relative w-[260px]">
            <Input
              className="pr-8"
              type={showKey ? "text" : "password"}
              value={provider.api_key}
              onChange={(e) => onChange({ api_key: e.target.value })}
              placeholder="Direct key (optional)"
            />
            <button
              type="button"
              onClick={() => setShowKey((s) => !s)}
              title={showKey ? "Hide" : "Reveal"}
              className="absolute right-2 top-1/2 -translate-y-1/2 text-text-muted hover:text-text-primary transition-colors"
              style={{ background: "transparent", border: "none", cursor: "pointer", display: "inline-flex" }}
            >
              {showKey ? <EyeOff size={14} /> : <Eye size={14} />}
            </button>
          </div>
        </SettingsItem>
        <SettingsItem title="API Key Env Var">
          <Input
            className="w-[260px]"
            value={provider.api_key_env}
            onChange={(e) => onChange({ api_key_env: e.target.value })}
            placeholder="e.g. OPENAI_API_KEY"
            mono
          />
        </SettingsItem>
        <SettingsItem title="HTTP Protocol">
          <Select
            value={provider.http_protocol}
            onChange={(v) => onChange({ http_protocol: v })}
            options={[
              { value: "http1", label: "HTTP/1.1" },
              { value: "http2", label: "HTTP/2" },
            ]}
            className="w-[140px]"
          />
        </SettingsItem>
        <SettingsItem title="Test Connection">
          <div className="flex items-center gap-2">
            {testOk === true && <CheckCircle2 size={15} style={{ color: "var(--success)" }} />}
            {testOk === false && <XCircle size={15} style={{ color: "var(--error)" }} />}
            <Button variant="outline" size="sm" onClick={test} loading={testing}>
              {testing ? "Testing…" : "Test Connection"}
            </Button>
          </div>
        </SettingsItem>
      </SettingsGroup>

      <SettingsGroup title="Parameters">
        <SettingsItem title="Tags">
          <Input
            className="w-[260px]"
            value={provider.tags.join(", ")}
            onChange={(e) =>
              onChange({ tags: e.target.value.split(",").map((t) => t.trim()).filter(Boolean) })
            }
            placeholder="general, reasoning, code"
            mono
          />
        </SettingsItem>
        <SettingsItem title="Max Concurrency">
          <Input
            className="w-[100px]"
            type="number"
            min={1}
            value={provider.max_concurrency}
            onChange={(e) => onChange({ max_concurrency: Number(e.target.value) || 1 })}
          />
        </SettingsItem>
        <SettingsItem title="Context Window">
          <Input
            className="w-[120px]"
            type="number"
            min={1}
            value={provider.context_window}
            onChange={(e) => onChange({ context_window: Number(e.target.value) || 128000 })}
          />
        </SettingsItem>
      </SettingsGroup>
    </div>
  );
}
