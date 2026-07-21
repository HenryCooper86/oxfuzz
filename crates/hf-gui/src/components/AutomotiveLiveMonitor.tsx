import { useState } from "react";
import { Radio, ShieldAlert } from "lucide-react";
import { useI18n } from "../i18nContext";
import {
  liveMonitorAutomotive,
  type AutomotiveProtocol,
  type AutomotiveSettings,
} from "../lib/automotive";
import { useToast } from "./ui/toastContext";
import { Badge, Button, Select } from "./ui";

interface AutomotiveLiveMonitorProps {
  projectRoot: string;
  settings: AutomotiveSettings;
  protocol: AutomotiveProtocol;
  onOperation: () => void;
}

/**
 * Trigger a bounded, read-only live capture on an allowlisted virtual CAN
 * interface. The result is retained as a capture-analysis operation and appears
 * in the operation history; physical-bench live capture is not offered here.
 */
export function AutomotiveLiveMonitor({
  projectRoot,
  settings,
  protocol,
  onOperation,
}: AutomotiveLiveMonitorProps) {
  const { t } = useI18n();
  const { toast } = useToast();
  const interfaces = settings.virtual_interfaces;
  const [iface, setIface] = useState(interfaces[0] ?? "vcan0");
  const [busy, setBusy] = useState(false);
  const ready =
    settings.enabled && settings.allowed_modes.includes("virtual_can") && interfaces.length > 0;

  async function start() {
    if (!ready || busy) return;
    setBusy(true);
    try {
      const outcome = await liveMonitorAutomotive({ projectRoot, interface: iface, protocol });
      toast({
        title: t("automotive.live.started"),
        description: t("automotive.evidenceRetained", { path: outcome.artifact_dir }),
        variant: "success",
      });
      onOperation();
    } catch (reason) {
      toast({
        title: t("automotive.live.failed"),
        description: String(reason),
        variant: "error",
      });
    } finally {
      setBusy(false);
    }
  }

  return (
    <section className="surface-card flex flex-col gap-3" style={{ padding: "var(--space-md)" }}>
      <div className="flex items-center gap-2">
        <Radio size={17} className="text-accent" />
        <h2 className="text-sm font-semibold">{t("automotive.live.title")}</h2>
        <Badge variant="warning">{t("automotive.live.virtualOnly")}</Badge>
      </div>
      <p className="text-12px text-text-secondary">{t("automotive.live.description")}</p>
      <div className="flex flex-wrap items-center gap-2">
        <Select
          value={iface}
          onChange={setIface}
          options={interfaces.map((name) => ({ value: name, label: name }))}
          disabled={!ready}
          className="min-w-32"
        />
        <Button variant="primary" loading={busy} disabled={!ready || busy} onClick={() => void start()}>
          {t("automotive.live.start")}
        </Button>
      </div>
      {!ready && (
        <div className="flex items-start gap-2 text-11px text-text-muted">
          <ShieldAlert size={14} className="shrink-0 text-warning" />
          <span>{t("automotive.live.gated")}</span>
        </div>
      )}
    </section>
  );
}
