import { useState } from "react";
import { ScanSearch, ShieldAlert, ShieldCheck } from "lucide-react";
import { useI18n } from "../i18nContext";
import {
  READ_ONLY_UDS_SERVICES,
  scanUdsAutomotive,
  type AutomotiveSettings,
  type UdsEcuView,
} from "../lib/automotive";
import { useToast } from "./ui/toastContext";
import { Badge, Button, Input, Select } from "./ui";

interface AutomotiveUdsScanProps {
  projectRoot: string;
  settings: AutomotiveSettings;
  onOperation: () => void;
}

function hex(value: number, width: number): string {
  return `0x${value.toString(16).toUpperCase().padStart(width, "0")}`;
}

function parseRequestIds(text: string): number[] {
  return text
    .split(",")
    .map((token) => token.trim())
    .filter(Boolean)
    .map((token) => (token.toLowerCase().startsWith("0x") ? parseInt(token, 16) : parseInt(token, 10)))
    .filter((value) => Number.isFinite(value) && value >= 0);
}

/**
 * Read-only UDS ECU/service discovery on an allowlisted virtual CAN interface.
 * Only read-only discovery services are offered; the service rejects anything
 * else before dispatch. Physical bench is not offered here.
 */
export function AutomotiveUdsScan({ projectRoot, settings, onOperation }: AutomotiveUdsScanProps) {
  const { t } = useI18n();
  const { toast } = useToast();
  const interfaces = settings.virtual_interfaces;
  const [iface, setIface] = useState(interfaces[0] ?? "vcan0");
  const [requestIdsText, setRequestIdsText] = useState("0x7e0");
  const [services, setServices] = useState<number[]>([0x3e, 0x22]);
  const [busy, setBusy] = useState(false);
  const [ecus, setEcus] = useState<UdsEcuView[] | null>(null);
  const ready =
    settings.enabled && settings.allowed_modes.includes("virtual_can") && interfaces.length > 0;

  function toggleService(sid: number) {
    setServices((prev) => (prev.includes(sid) ? prev.filter((value) => value !== sid) : [...prev, sid]));
  }

  async function scan() {
    const requestIds = parseRequestIds(requestIdsText);
    if (!ready || busy || services.length === 0 || requestIds.length === 0) return;
    setBusy(true);
    try {
      const outcome = await scanUdsAutomotive({ projectRoot, interface: iface, requestIds, services });
      setEcus(outcome.result.data.ecus);
      toast({
        title: t("automotive.uds.scanned", { count: outcome.result.data.ecus.length }),
        variant: "success",
      });
      onOperation();
    } catch (reason) {
      toast({ title: t("automotive.uds.failed"), description: String(reason), variant: "error" });
    } finally {
      setBusy(false);
    }
  }

  return (
    <section className="surface-card flex flex-col gap-3" style={{ padding: "var(--space-md)" }}>
      <div className="flex items-center gap-2">
        <ScanSearch size={17} className="text-accent" />
        <h2 className="text-sm font-semibold">{t("automotive.uds.title")}</h2>
        <Badge variant="success">
          <span className="inline-flex items-center gap-1">
            <ShieldCheck size={11} aria-hidden="true" />
            {t("automotive.uds.readOnly")}
          </span>
        </Badge>
      </div>
      <p className="text-12px text-text-secondary">{t("automotive.uds.description")}</p>

      <div className="flex flex-wrap items-end gap-3">
        <Select
          value={iface}
          onChange={setIface}
          options={interfaces.map((name) => ({ value: name, label: name }))}
          disabled={!ready}
          className="min-w-28"
        />
        <label className="flex flex-col gap-1 text-11px text-text-muted">
          {t("automotive.uds.requestIds")}
          <Input
            mono
            value={requestIdsText}
            disabled={!ready}
            onChange={(event) => setRequestIdsText(event.target.value)}
            placeholder="0x7e0, 0x7e1"
            className="w-40"
          />
        </label>
      </div>

      <div>
        <div className="mb-1 text-11px font-semibold uppercase text-text-muted">
          {t("automotive.uds.services")}
        </div>
        <div className="flex flex-wrap gap-2">
          {READ_ONLY_UDS_SERVICES.map((service) => (
            <label
              key={service.sid}
              className="flex items-center gap-2 rounded-md border border-border bg-surface-primary px-3 py-1.5 text-11px"
            >
              <input
                type="checkbox"
                checked={services.includes(service.sid)}
                disabled={!ready}
                onChange={() => toggleService(service.sid)}
              />
              <span className="font-mono text-text-muted">{hex(service.sid, 2)}</span>
              {service.label}
            </label>
          ))}
        </div>
      </div>

      <div>
        <Button
          variant="primary"
          loading={busy}
          disabled={!ready || busy || services.length === 0}
          onClick={() => void scan()}
        >
          {t("automotive.uds.scan")}
        </Button>
      </div>

      {!ready && (
        <div className="flex items-start gap-2 text-11px text-text-muted">
          <ShieldAlert size={14} className="shrink-0 text-warning" />
          <span>{t("automotive.uds.gated")}</span>
        </div>
      )}

      {ecus && (
        ecus.length === 0 ? (
          <div className="rounded-md border border-dashed border-border px-3 py-4 text-center text-12px text-text-muted">
            {t("automotive.uds.noEcus")}
          </div>
        ) : (
          <div className="flex flex-col gap-2">
            {ecus.map((ecu) => (
              <div key={ecu.request_id} className="rounded-md border border-border bg-surface-primary p-2">
                <div className="mb-1 font-mono text-11px text-text-primary">
                  {hex(ecu.request_id, 3)} {"->"} {hex(ecu.response_id, 3)}
                </div>
                <div className="flex flex-wrap gap-1">
                  {ecu.services.map((service) => (
                    <Badge key={service.sid} variant={service.supported ? "success" : "default"}>
                      {hex(service.sid, 2)}
                      {service.supported
                        ? " ok"
                        : ` NRC ${service.nrc === null ? "?" : hex(service.nrc, 2)}`}
                    </Badge>
                  ))}
                </div>
              </div>
            ))}
          </div>
        )
      )}
    </section>
  );
}
