// Observability panel -- live system state (providers, agent pool, memory).
//
// Ported from y-agent's panel, re-typed to hobot's `system_snapshot` command:
// per-provider health + usage (concurrency, requests/errors, tokens, cost),
// the agent pool, and runtime memory counters. Polls every 5s. Rendered inside
// the app's PanelShell (which supplies the title/close chrome).

import { useEffect, useState } from "react";
import { Server, Bot, ChevronDown, ChevronRight } from "lucide-react";
import { getTransport } from "../../lib";
import "./ObservabilityPanel.css";

interface ProviderSnapshot {
  id: string;
  model: string;
  tags: string[];
  is_frozen: boolean;
  active_requests: number;
  max_concurrency: number;
  total_requests: number;
  total_errors: number;
  error_rate: number;
  total_input_tokens: number;
  total_output_tokens: number;
  estimated_cost_usd: number;
}
interface AgentInstanceSnapshot {
  instance_id: string;
  agent_name: string;
  state: string;
  elapsed_ms: number;
  iterations: number;
  tokens_used: number;
}
interface AgentPoolSnapshot {
  active_instances: number;
  available_slots: number;
  total_instances: number;
  instances: AgentInstanceSnapshot[];
}
interface MemorySnapshot {
  pending_runs: number;
  interrupted_runs: number;
  llm_calls: number;
  targets: number;
  crashes: number;
}
interface SystemSnapshot {
  providers: ProviderSnapshot[];
  agents: AgentPoolSnapshot;
  memory: MemorySnapshot;
}

const n = (v: number) => v.toLocaleString();

function ProviderCard({ p }: { p: ProviderSnapshot }) {
  const pct = p.max_concurrency > 0 ? (p.active_requests / p.max_concurrency) * 100 : 0;
  const fillClass = pct >= 100 ? "full" : pct >= 75 ? "high" : "";
  return (
    <div className="obs-provider-card">
      <div className="obs-provider-identity">
        <div className="obs-provider-icon">
          <Server size={12} />
        </div>
        <span className="obs-provider-name">{p.id}</span>
        <span className="obs-provider-model">{p.model}</span>
        <span className={`obs-badge ${p.is_frozen ? "obs-badge-frozen" : "obs-badge-healthy"}`}>
          {p.is_frozen ? "FROZEN" : "OK"}
        </span>
      </div>

      {p.tags.length > 0 && (
        <div className="obs-tags">
          {p.tags.map((tag) => (
            <span key={tag} className="obs-tag">{tag}</span>
          ))}
        </div>
      )}

      <div className="obs-concurrency">
        <div className="obs-concurrency-label">
          <span className="obs-concurrency-text">CONCURRENCY</span>
          <span className="obs-concurrency-text">{p.active_requests} / {p.max_concurrency}</span>
        </div>
        <div className="obs-concurrency-bar">
          <div className={`obs-concurrency-fill ${fillClass}`} style={{ width: `${Math.min(pct, 100)}%` }} />
        </div>
      </div>

      <div className="obs-metrics">
        <Metric label="Requests" value={n(p.total_requests)} />
        <Metric label="Errors" value={n(p.total_errors)} />
        <Metric label="Err Rate" value={`${(p.error_rate * 100).toFixed(1)}%`} />
        <Metric label="In Tokens" value={n(p.total_input_tokens)} />
        <Metric label="Out Tokens" value={n(p.total_output_tokens)} />
        <Metric label="Cost" value={`$${p.estimated_cost_usd.toFixed(4)}`} />
      </div>
    </div>
  );
}

function Metric({ label, value }: { label: string; value: string }) {
  return (
    <div className="obs-metric">
      <span className="obs-metric-label">{label}</span>
      <span className="obs-metric-value">{value}</span>
    </div>
  );
}

function Section({
  title,
  count,
  open,
  onToggle,
  children,
}: {
  title: string;
  count?: number;
  open: boolean;
  onToggle: () => void;
  children: React.ReactNode;
}) {
  return (
    <div className="obs-section">
      <button
        type="button"
        className="obs-section-header"
        onClick={onToggle}
        aria-expanded={open}
        style={{ width: "100%", background: "none", border: "none", font: "inherit", color: "inherit", textAlign: "left" }}
      >
        <span className="obs-section-chevron">{open ? <ChevronDown size={14} /> : <ChevronRight size={14} />}</span>
        <span className="obs-section-title">{title}</span>
        {count !== undefined && <span className="obs-section-count">{count}</span>}
      </button>
      {open && children}
    </div>
  );
}

export function ObservabilityPanel() {
  const [snap, setSnap] = useState<SystemSnapshot | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [providersOpen, setProvidersOpen] = useState(true);
  const [agentsOpen, setAgentsOpen] = useState(true);
  const [memoryOpen, setMemoryOpen] = useState(false);

  useEffect(() => {
    let cancelled = false;
    const tick = () => {
      getTransport()
        .invoke<SystemSnapshot>("system_snapshot")
        .then((d) => {
          if (!cancelled && d) {
            setSnap(d);
            setError(null);
          }
        })
        // Keep the last good snapshot on a transient poll failure; only surface
        // an error (instead of an eternal "Loading...") when we have nothing.
        .catch((e) => !cancelled && setError(String(e)));
    };
    tick();
    const id = setInterval(tick, 5000);
    return () => {
      cancelled = true;
      clearInterval(id);
    };
  }, []);

  const providerCount = snap?.providers.length ?? 0;
  const activeAgents = snap?.agents.active_instances ?? 0;
  const slots = snap?.agents.available_slots ?? 0;

  return (
    <div className="obs-panel">
      {/* Summary bar */}
      <div className="obs-summary">
        <div className="obs-summary-item">
          <span className="obs-summary-value">{providerCount}</span>
          <span className="obs-summary-label">providers</span>
        </div>
        <div className="obs-summary-item">
          <span className="obs-summary-value">{activeAgents}</span>
          <span className="obs-summary-label">agents</span>
        </div>
        <div className="obs-summary-item">
          <span className="obs-summary-value">{slots}</span>
          <span className="obs-summary-label">slots</span>
        </div>
      </div>

      <div className="obs-content">
        {!snap ? (
          <div className="obs-empty">
            <Server size={24} className="obs-empty-icon" />
            <p className="obs-empty-text">
              {error ? `Failed to load system state: ${error}` : "Loading system state..."}
            </p>
          </div>
        ) : (
          <>
            <Section title="Provider Pool" count={providerCount} open={providersOpen} onToggle={() => setProvidersOpen(!providersOpen)}>
              {snap.providers.length === 0 ? (
                <div className="obs-no-items">No LLM provider configured</div>
              ) : (
                snap.providers.map((p) => <ProviderCard key={p.id} p={p} />)
              )}
            </Section>

            <Section title="Agent Pool" count={snap.agents.total_instances} open={agentsOpen} onToggle={() => setAgentsOpen(!agentsOpen)}>
              {snap.agents.instances.length === 0 ? (
                <div className="obs-no-items">
                  No active agent instances ({slots} available)
                </div>
              ) : (
                snap.agents.instances.map((a) => (
                  <div key={a.instance_id} className="obs-agent-card">
                    <div className="obs-agent-header">
                      <div className="obs-agent-icon">
                        <Bot size={12} />
                      </div>
                      <span className="obs-agent-name">{a.agent_name}</span>
                      <span className="obs-agent-state">{a.state}</span>
                    </div>
                  </div>
                ))
              )}
            </Section>

            <Section title="Memory" open={memoryOpen} onToggle={() => setMemoryOpen(!memoryOpen)}>
              <div className="obs-provider-card">
                <div className="obs-metrics">
                  <Metric label="Pending Runs" value={n(snap.memory.pending_runs)} />
                  <Metric label="Interrupted Runs" value={n(snap.memory.interrupted_runs)} />
                  <Metric label="LLM Calls" value={n(snap.memory.llm_calls)} />
                  <Metric label="Targets" value={n(snap.memory.targets)} />
                  <Metric label="Crashes" value={n(snap.memory.crashes)} />
                </div>
              </div>
            </Section>
          </>
        )}
      </div>
    </div>
  );
}
