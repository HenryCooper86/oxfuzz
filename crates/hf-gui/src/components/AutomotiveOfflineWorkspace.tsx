import { useState } from "react";
import { Activity, FileSearch, GitCompare, Upload } from "lucide-react";
import { useI18n } from "../i18nContext";
import { isTauriEnvironment, pickFile } from "../lib";
import {
  diffAutomotiveCaptures,
  importAutomotiveCapture,
  OFFLINE_CAPTURE_FORMAT_OPTIONS,
  type CaptureDiffView,
  type CaptureImport,
  type OfflineCaptureFormat,
  type OfflineChangeMap,
  type OfflineFrameIdentity,
  type OfflineFrameView,
  type ProtocolStateLabelView,
} from "../lib/automotive";
import { useToast } from "./ui/toastContext";
import { AutomotiveSignalGraph } from "./AutomotiveSignalGraph";
import { Badge, Button, Select } from "./ui";

/** Rows rendered in the frame grid; the service already caps the payload. */
const FRAME_DISPLAY_CAP = 500;
/** Change-map rows shown in the sniffer table. */
const SNIFFER_ID_CAP = 40;

function displayName(path: string): string {
  return path.split(/[\\/]/).filter(Boolean).pop() ?? path;
}

function formatId(id: number, extended: boolean): string {
  return `0x${id.toString(16).toUpperCase().padStart(extended ? 8 : 3, "0")}`;
}

function formatSeconds(micros: number): string {
  return (micros / 1_000_000).toFixed(6);
}

function formatProtocolState(state: ProtocolStateLabelView): string {
  const service = `0x${state.service.toString(16).toUpperCase().padStart(2, "0")}`;
  const detail =
    state.detail === null
      ? ""
      : ` / 0x${state.detail.toString(16).toUpperCase().padStart(2, "0")}`;
  return `${state.kind.replaceAll("_", " ")} ${service}${detail}`;
}

function SnifferRow({ map }: { map: OfflineChangeMap }) {
  return (
    <div className="flex items-center gap-2 text-11px">
      <span className="font-mono text-text-secondary" style={{ width: 74 }}>
        {formatId(map.id, map.extended)}
      </span>
      <div className="flex gap-1">
        {map.byte_changed.map((changed, index) => (
          <span
            key={index}
            title={`byte ${index}: ${map.distinct_values[index]} distinct`}
            className="inline-flex items-center justify-center rounded font-mono"
            style={{
              width: 22,
              height: 18,
              fontSize: 10,
              color: changed ? "var(--accent)" : "var(--text-muted)",
              background: changed ? "var(--accent-subtle)" : "var(--surface-primary)",
              border: "1px solid var(--border)",
            }}
          >
            {index}
          </span>
        ))}
      </div>
      <span className="ml-auto text-text-muted">{map.observations}</span>
    </div>
  );
}

function FrameRow({ frame }: { frame: OfflineFrameView }) {
  const signals = frame.signals
    .map((signal) => `${signal.name}=${signal.label ?? signal.value}${signal.unit ? ` ${signal.unit}` : ""}`)
    .join("  ");
  return (
    <tr className="border-t border-border">
      <td className="px-2 py-1 font-mono text-text-muted">{formatSeconds(frame.timestamp_micros)}</td>
      <td className="px-2 py-1 font-mono">{formatId(frame.id, frame.extended)}</td>
      <td className="px-2 py-1 text-text-muted">{frame.direction ?? ""}</td>
      <td className="px-2 py-1 text-text-muted">{frame.data_hex.length / 2}</td>
      <td className="px-2 py-1 font-mono break-all">{frame.data_hex}</td>
      <td className="px-2 py-1 text-text-secondary">
        {frame.message ? <span className="text-accent">{frame.message}</span> : null}
        {signals ? <span className="ml-2 font-mono">{signals}</span> : null}
      </td>
    </tr>
  );
}

export function AutomotiveOfflineWorkspace() {
  const { t } = useI18n();
  const { toast } = useToast();
  const desktop = isTauriEnvironment();
  const [format, setFormat] = useState<OfflineCaptureFormat>("candump");
  const [capturePath, setCapturePath] = useState("");
  const [dbcPath, setDbcPath] = useState("");
  const [result, setResult] = useState<CaptureImport | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [secondPath, setSecondPath] = useState("");
  const [diff, setDiff] = useState<CaptureDiffView | null>(null);
  const [diffBusy, setDiffBusy] = useState(false);

  async function analyze() {
    if (!desktop || !capturePath || busy) return;
    setBusy(true);
    setError(null);
    try {
      const next = await importAutomotiveCapture({
        capturePath,
        format,
        dbcPath: dbcPath || null,
      });
      setResult(next);
    } catch (reason) {
      const message = String(reason);
      setError(message);
      toast({ title: t("automotive.offline.analyzeFailed"), description: message, variant: "error" });
    } finally {
      setBusy(false);
    }
  }

  async function compare() {
    if (!desktop || !capturePath || !secondPath || diffBusy) return;
    setDiffBusy(true);
    setError(null);
    try {
      const next = await diffAutomotiveCaptures({ firstPath: capturePath, secondPath, format });
      setDiff(next);
    } catch (reason) {
      const message = String(reason);
      setError(message);
      toast({ title: t("automotive.offline.analyzeFailed"), description: message, variant: "error" });
    } finally {
      setDiffBusy(false);
    }
  }

  return (
    <section className="surface-card flex flex-col gap-3" style={{ padding: "var(--space-md)" }}>
      <div className="flex items-center gap-2">
        <FileSearch size={17} className="text-accent" />
        <h2 className="text-sm font-semibold">{t("automotive.offline.title")}</h2>
        <Badge variant="success">{t("automotive.noLiveTraffic")}</Badge>
      </div>
      <p className="text-12px text-text-secondary">{t("automotive.offline.description")}</p>

      {!desktop && (
        <div role="note" className="text-12px text-text-muted">
          {t("automotive.offline.desktopOnly")}
        </div>
      )}

      <div className="flex flex-wrap items-center gap-2">
        <Select
          value={format}
          onChange={(next) => setFormat(next as OfflineCaptureFormat)}
          options={OFFLINE_CAPTURE_FORMAT_OPTIONS}
          className="min-w-40"
        />
        <Button
          variant="outline"
          disabled={!desktop}
          onClick={() => void pickFile(t("automotive.offline.selectCapture")).then((p) => p && setCapturePath(p))}
        >
          <Upload size={14} />
          {capturePath ? displayName(capturePath) : t("automotive.offline.selectCapture")}
        </Button>
        <Button
          variant="ghost"
          disabled={!desktop}
          onClick={() => void pickFile(t("automotive.offline.loadDbc")).then((p) => p && setDbcPath(p))}
        >
          {dbcPath ? displayName(dbcPath) : t("automotive.offline.loadDbc")}
        </Button>
        <Button
          variant="primary"
          loading={busy}
          disabled={!desktop || !capturePath || busy}
          onClick={() => void analyze()}
        >
          {t("automotive.offline.analyze")}
        </Button>
      </div>

      {error && (
        <div role="alert" className="text-12px text-error">
          {error}
        </div>
      )}

      {result && (
        <>
          <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
            {[
              [t("automotive.offline.frames"), result.frame_count],
              [t("automotive.offline.uniqueIds"), result.unique_ids],
              [t("automotive.offline.rate"), `${result.frames_per_second.toFixed(1)}/s`],
              [t("automotive.offline.duration"), `${formatSeconds(result.duration_micros)}s`],
            ].map(([label, value]) => (
              <div key={String(label)} className="rounded-md border border-border bg-surface-primary p-3">
                <div className="text-lg font-semibold text-text-primary">{value}</div>
                <div className="text-11px text-text-muted">{label}</div>
              </div>
            ))}
          </div>
          {result.dbc_message_count > 0 && (
            <Badge variant="accent">
              {t("automotive.offline.dbcLoaded", { count: result.dbc_message_count })}
            </Badge>
          )}

          <div className="flex items-center gap-2">
            <Activity size={15} className="text-accent" />
            <h3 className="text-12px font-semibold">{t("automotive.offline.sniffer")}</h3>
          </div>
          <p className="text-11px text-text-muted">{t("automotive.offline.snifferHint")}</p>
          <div className="flex flex-col gap-1.5">
            {result.change_maps.slice(0, SNIFFER_ID_CAP).map((map) => (
              <SnifferRow key={`${map.id}-${map.extended}`} map={map} />
            ))}
          </div>

          <div className="flex items-center gap-2">
            <Activity size={15} className="text-accent" />
            <h3 className="text-12px font-semibold">
              {t("automotive.offline.protocolStates")}
            </h3>
          </div>
          <p className="text-11px text-text-muted">
            {t("automotive.offline.protocolStatesHint")}
          </p>
          <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
            {[
              [t("automotive.offline.completedPdus"), result.protocol_states.completed_pdus],
              [t("automotive.offline.uniqueStates"), result.protocol_states.unique_states.length],
              [
                t("automotive.offline.uniqueTransitions"),
                result.protocol_states.transitions.length,
              ],
              [t("automotive.offline.malformedFrames"), result.protocol_states.malformed_frames],
            ].map(([label, value]) => (
              <div
                key={String(label)}
                className="rounded-md border border-border bg-surface-primary p-2"
              >
                <div className="font-semibold text-text-primary">{value}</div>
                <div className="text-11px text-text-muted">{label}</div>
              </div>
            ))}
          </div>
          {result.protocol_states.transitions.length > 0 && (
            <div className="flex flex-col gap-1 text-11px">
              {result.protocol_states.transitions.slice(0, 40).map((transition, index) => (
                <div
                  key={`${transition.stream.channel}-${transition.stream.frame.id}-${transition.stream.frame.extended}-${index}`}
                  className="rounded border border-border bg-surface-primary px-2 py-1 font-mono text-text-secondary"
                >
                  {formatId(transition.stream.frame.id, transition.stream.frame.extended)}: {formatProtocolState(transition.from)} → {formatProtocolState(transition.to)} ×{transition.count}
                </div>
              ))}
            </div>
          )}

          <h3 className="text-12px font-semibold">{t("automotive.offline.frameGrid")}</h3>
          {result.truncated && (
            <div className="text-11px text-warning">
              {t("automotive.offline.truncated", {
                shown: Math.min(result.frames.length, FRAME_DISPLAY_CAP),
                total: result.frame_count,
              })}
            </div>
          )}
          <div className="overflow-x-auto rounded-md border border-border">
            <table className="w-full text-11px">
              <thead className="text-text-muted">
                <tr>
                  <th className="px-2 py-1 text-left">t (s)</th>
                  <th className="px-2 py-1 text-left">ID</th>
                  <th className="px-2 py-1 text-left">Dir</th>
                  <th className="px-2 py-1 text-left">Len</th>
                  <th className="px-2 py-1 text-left">Data</th>
                  <th className="px-2 py-1 text-left">{t("automotive.offline.decoded")}</th>
                </tr>
              </thead>
              <tbody>
                {result.frames.slice(0, FRAME_DISPLAY_CAP).map((frame, index) => (
                  <FrameRow key={index} frame={frame} />
                ))}
              </tbody>
            </table>
          </div>
          <AutomotiveSignalGraph frames={result.frames} />
        </>
      )}

      <div className="mt-1 flex flex-col gap-2 border-t border-border pt-3">
        <div className="flex items-center gap-2">
          <GitCompare size={15} className="text-accent" />
          <h3 className="text-12px font-semibold">{t("automotive.offline.diffTitle")}</h3>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <Button
            variant="outline"
            disabled={!desktop}
            onClick={() => void pickFile(t("automotive.offline.selectSecond")).then((p) => p && setSecondPath(p))}
          >
            <Upload size={14} />
            {secondPath ? displayName(secondPath) : t("automotive.offline.selectSecond")}
          </Button>
          <Button
            variant="primary"
            loading={diffBusy}
            disabled={!desktop || !capturePath || !secondPath || diffBusy}
            onClick={() => void compare()}
          >
            {t("automotive.offline.compare")}
          </Button>
        </div>
        {diff && (
          <div className="grid grid-cols-1 gap-2 sm:grid-cols-3 text-11px">
            {([
              [t("automotive.offline.onlyFirst"), diff.only_in_first],
              [t("automotive.offline.onlySecond"), diff.only_in_second],
              [t("automotive.offline.changed"), diff.changed],
            ] satisfies Array<[string, OfflineFrameIdentity[]]>).map(([label, ids]) => (
              <div key={String(label)} className="rounded-md border border-border bg-surface-primary p-2">
                <div className="mb-1 font-semibold text-text-secondary">
                  {label}{" "}
                  <span className="text-text-muted">
                    ({ids.length})
                  </span>
                </div>
                <div className="flex flex-wrap gap-1">
                  {ids.slice(0, 60).map((identity) => (
                    <span
                      key={`${identity.id}-${identity.extended}`}
                      className="font-mono text-text-muted"
                    >
                      {formatId(identity.id, identity.extended)}
                    </span>
                  ))}
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </section>
  );
}
