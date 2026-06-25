import type { ReactNode } from "react";
import { Puzzle, BookOpen, Zap, Target, FileCode, Activity, Bug } from "lucide-react";

// ---------------------------------------------------------------------------
// Shared scaffolding
// ---------------------------------------------------------------------------

function ViewHeader({ title, description }: { title: string; description: string }) {
  return (
    <div>
      <h1 className="text-xl font-semibold">{title}</h1>
      <p className="text-sm text-text-secondary mt-0.5">{description}</p>
    </div>
  );
}

function EmptyState({ icon, hint }: { icon: ReactNode; hint: string }) {
  return (
    <div
      className="surface-card flex flex-col items-center justify-center text-center"
      style={{ padding: "var(--space-xl) var(--space-md)" }}
    >
      <div
        className="flex items-center justify-center mb-3 rounded-full"
        style={{ width: "48px", height: "48px", background: "var(--accent-subtle)", border: "1px solid var(--border)" }}
      >
        <span style={{ color: "var(--accent)" }}>{icon}</span>
      </div>
      <p className="text-sm text-text-secondary max-w-sm">{hint}</p>
      <span
        className="text-xs mt-3 px-2 py-0.5 rounded-sm"
        style={{ background: "var(--surface-active)", color: "var(--text-muted)" }}
      >
        Coming soon
      </span>
    </div>
  );
}

function Card({ icon, title, subtitle }: { icon: ReactNode; title: string; subtitle: string }) {
  return (
    <div className="surface-card flex items-start gap-3" style={{ padding: "var(--space-md)" }}>
      <div
        className="flex items-center justify-center shrink-0 rounded-md"
        style={{ width: "34px", height: "34px", background: "var(--accent-subtle)", border: "1px solid var(--border)" }}
      >
        <span style={{ color: "var(--accent)" }}>{icon}</span>
      </div>
      <div className="flex flex-col min-w-0">
        <span className="text-sm font-medium">{title}</span>
        <span className="text-xs text-text-secondary mt-0.5">{subtitle}</span>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Agents
// ---------------------------------------------------------------------------

const AGENTS = [
  { icon: <Target size={16} />, title: "Discovery", subtitle: "Scans projects and ranks fuzzing targets." },
  { icon: <FileCode size={16} />, title: "Harness", subtitle: "Authors and compiles harnesses per target." },
  { icon: <Activity size={16} />, title: "Coverage", subtitle: "Grows corpora and tracks coverage deltas." },
  { icon: <Bug size={16} />, title: "Triage", subtitle: "Dedupes crashes and drafts bug reports." },
];

export function AgentsView() {
  return (
    <div className="flex flex-col gap-4" style={{ animation: "fadeIn 0.2s ease" }}>
      <ViewHeader title="Agents" description="Specialized sub-agents that discover targets, write harnesses, and triage crashes." />
      <div className="grid grid-cols-2 gap-3">
        {AGENTS.map((a) => (
          <Card key={a.title} icon={a.icon} title={a.title} subtitle={a.subtitle} />
        ))}
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Skills
// ---------------------------------------------------------------------------

const SKILLS = [
  { title: "harness-author", subtitle: "Generates compile-validated fuzz harnesses for a target." },
  { title: "crash-triage", subtitle: "Classifies and minimizes crashes by stack signature." },
  { title: "target-triage", subtitle: "Heuristics for ranking functions worth fuzzing." },
];

export function SkillsView() {
  return (
    <div className="flex flex-col gap-4" style={{ animation: "fadeIn 0.2s ease" }}>
      <ViewHeader title="Skills" description="Reusable, self-evolving skills the agent applies across runs." />
      <div className="flex flex-col gap-2">
        {SKILLS.map((s) => (
          <Card key={s.title} icon={<Puzzle size={16} />} title={s.title} subtitle={s.subtitle} />
        ))}
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Knowledge
// ---------------------------------------------------------------------------

export function KnowledgeView() {
  return (
    <div className="flex flex-col gap-4" style={{ animation: "fadeIn 0.2s ease" }}>
      <ViewHeader title="Knowledge" description="RAG over project source, fuzzer documentation, and CVE patterns." />
      <EmptyState icon={<BookOpen size={20} />} hint="Indexed knowledge sources will appear here once you add documents or enable retrieval." />
    </div>
  );
}

// ---------------------------------------------------------------------------
// Automation
// ---------------------------------------------------------------------------

export function AutomationView() {
  return (
    <div className="flex flex-col gap-4" style={{ animation: "fadeIn 0.2s ease" }}>
      <ViewHeader title="Automation" description="Scheduled campaigns and recurring fuzzing workflows." />
      <EmptyState icon={<Zap size={20} />} hint="Scheduled and recurring fuzzing tasks will appear here once you create an automation." />
    </div>
  );
}
