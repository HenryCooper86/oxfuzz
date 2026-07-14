// Engines tab -- configure AFL++, honggfuzz, libFuzzer, ClusterFuzzLite, syzkaller.
// Controlled: reads/writes the parsed `engines` config object via props. The
// config shape is `engines = [{ kind, enabled, default_duration_secs, ... }]`.

import { Input } from "../ui/Input";
import { Switch } from "../ui/Switch";
import { Badge } from "../ui/Badge";
import { SettingsGroup, SettingsItem } from "../ui/SettingsGroup";
import { Crosshair, Bug, Zap, Cloud, Cpu } from "lucide-react";
import { useI18n } from "../../i18n";

type Cfg = Record<string, unknown>;
type Engine = Record<string, unknown>;

// Display metadata keyed by engine `kind`. Falls back gracefully for unknowns.
const META: Record<string, { label: string; icon: React.ComponentType<{ size?: number }> }> = {
  libfuzzer: { label: "libFuzzer", icon: Zap },
  "afl++": { label: "AFL++", icon: Crosshair },
  honggfuzz: { label: "honggfuzz", icon: Bug },
  clusterfuzzlite: { label: "ClusterFuzzLite", icon: Cloud },
  syzkaller: { label: "syzkaller (kernel)", icon: Cpu },
};

export function EnginesTab({ value, onChange }: { value: Cfg; onChange: (next: Cfg) => void }) {
  const { t } = useI18n();
  const engines: Engine[] = Array.isArray(value.engines) ? (value.engines as Engine[]) : [];

  function patchEngine(i: number, patch: Engine) {
    const next = engines.map((e, idx) => (idx === i ? { ...e, ...patch } : e));
    onChange({ ...value, engines: next });
  }

  if (engines.length === 0) {
    return (
      <div className="text-text-muted text-sm" style={{ padding: "var(--space-md)" }}>
        {t("settings.engines.emptyPre")} <code>[[engines]]</code> {t("settings.engines.emptyPost")}
      </div>
    );
  }

  return (
    <div>
      {engines.map((e, idx) => {
        const kind = (e.kind as string) ?? `engine-${idx}`;
        const meta = META[kind] ?? { label: kind, icon: Crosshair };
        const Icon = meta.icon;
        const enabled = e.enabled !== false;
        const binary = (e.fuzz_bin as string) ?? "";
        const duration = (e.default_duration_secs as number) ?? 3600;
        const mem = (e.default_mem_mb as number) ?? 2048;
        const supports = Array.isArray(e.supports) ? (e.supports as string[]) : [];
        return (
          <SettingsGroup key={kind} title={meta.label} description={idx === 0 ? t("settings.engines.desc") : undefined}>
            <div style={{ padding: "10px 14px" }}>
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <Icon size={16} />
                  <span className="text-sm font-medium text-text-primary">{meta.label}</span>
                  {enabled ? <Badge variant="success">{t("settings.engines.enabled")}</Badge> : <Badge>{t("settings.engines.disabled")}</Badge>}
                </div>
                <Switch checked={enabled} onChange={(v) => patchEngine(idx, { enabled: v })} />
              </div>
            </div>
            <SettingsItem title={t("settings.engines.binary")}>
              <div style={{ width: 220 }}>
                <Input value={binary} onChange={(ev) => patchEngine(idx, { fuzz_bin: ev.target.value })} mono disabled={!enabled} placeholder={t("settings.engines.autoDetected")} />
              </div>
            </SettingsItem>
            <SettingsItem title={t("settings.engines.defaultDuration")}>
              <div style={{ width: 120 }}>
                <Input type="number" value={duration} onChange={(ev) => patchEngine(idx, { default_duration_secs: parseInt(ev.target.value) || 3600 })} disabled={!enabled} />
              </div>
            </SettingsItem>
            <SettingsItem title={t("settings.engines.defaultMemory")}>
              <div style={{ width: 120 }}>
                <Input type="number" value={mem} onChange={(ev) => patchEngine(idx, { default_mem_mb: parseInt(ev.target.value) || 2048 })} disabled={!enabled} />
              </div>
            </SettingsItem>
            <div className="settings-item" style={{ padding: "10px 14px" }}>
              <div className="flex gap-1">
                {supports.map((lang) => <Badge key={lang} variant="accent">{lang}</Badge>)}
              </div>
            </div>
          </SettingsGroup>
        );
      })}
    </div>
  );
}
