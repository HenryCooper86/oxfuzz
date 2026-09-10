import { RunHealthPages } from "./runHealthPages";
import type { Transport, RunOwner } from "../lib/transport";
import type { ToastContextValue } from "../components/ui/toastContext";
import type { RunOutputValue } from "./runOutput";
import {
  emptyRun,
  errorMessage,
  loadOutput,
  LOG_CAP,
  LOG_LINE_CAP,
  OWNER_REQUEST_CAP,
  RUN_CAP,
  HEALTH_CAP,
  serializeOutput,
  V1_KEY,
  V2_KEY,
  type OutputState,
  type RunData,
} from "./runOutputState";
import {
  activeStatus,
  compareTimestamps,
  count,
  newer,
  parseHealth,
  parseOwner,
  parseSummary,
  rate,
  record,
  timestamp,
  uuid,
  validStatus,
} from "./runOutputValidation";

type ReadToken = { epoch: number; dirty: boolean };

/** Owns one mounted provider's reads, subscriptions and bounded display cache. */
export class RunOutputController {
  state: OutputState = loadOutput();
  private listeners = new Set<() => void>();
  private epoch = 0;
  private mounted = false;
  private project = "";
  private scope = 0;
  private discovery = 0;
  private selection: string | null = null;
  private poll: ReturnType<typeof setInterval> | undefined;
  private pollId: string | null = null;
  private owners = new Map<string, Promise<void>>();
  private telemetry = new Map<string, ReadToken>();
  private healthPages: RunHealthPages;
  private statusVersions = new Map<string, number>();
  private summaryVersions = new Map<string, number>();
  private notified = new Set<string>();
  private lastPersisted: string | null = null;
  private invocation = 0;
  private cancelOnAdmission = false;
  private toast: ToastContextValue["toast"] = () => {};
  private setEngine: (engine: string | null) => void = () => {};

  constructor(private transport: Transport) {
    this.healthPages = new RunHealthPages(transport, {
      active: () => this.mounted,
      selectedId: () => this.selectedId(),
      scope: () => this.scope,
      epoch: () => this.epoch,
      patch: (id, update) => this.patch(id, update),
      remember: (id) => this.rememberHealth(id),
    });
  }
  subscribe = (listener: () => void) => {
    this.listeners.add(listener);
    return () => {
      this.listeners.delete(listener);
    };
  };
  getSnapshot = () => this.state;
  private emit() {
    for (const listener of this.listeners) listener();
    this.persist();
    this.syncSelection();
  }
  private persist() {
    const serialized = serializeOutput(this.state);
    if (serialized === this.lastPersisted) return;
    try {
      localStorage.setItem(V2_KEY, serialized);
      this.lastPersisted = serialized;
      if (!this.state.keepLegacySource) localStorage.removeItem(V1_KEY);
    } catch {
      // Summary persistence is best effort; a failed v2 write leaves v1 recoverable.
    }
  }
  configure(toast: ToastContextValue["toast"], setEngine: (engine: string | null) => void) {
    this.toast = toast;
    this.setEngine = setEngine;
  }
  start() {
    this.mounted = true;
    const epoch = ++this.epoch;
    const disposers: Array<() => void> = [];
    let active = true;
    const listen = (name: string, callback: (payload: unknown) => void) => {
      void this.transport
        .listen(name, ({ payload }) => {
          if (active && this.mounted && epoch === this.epoch) callback(payload);
        })
        .then((dispose) => {
          if (active) disposers.push(dispose);
          else dispose();
        })
        .catch(() => {
          // A failed optional stream registration leaves retained reads usable.
        });
    };
    listen("run:progress", (payload) => this.progress(payload));
    listen("run:status", (payload) => this.status(payload));
    listen("campaign:health", (payload) => this.liveHealth(payload));
    listen("stream:connected", () => this.reconnect());
    listen("stream:lagged", () => this.reconnect());
    this.persist();
    this.syncSelection();
    return () => {
      active = false;
      this.mounted = false;
      ++this.epoch;
      ++this.scope;
      ++this.discovery;
      for (const dispose of disposers) dispose();
      this.stopPoll();
      this.selection = null;
      this.owners.clear();
      this.telemetry.clear();
      this.healthPages.clear();
    };
  }
  selectProject(project: string) {
    this.project = project;
    ++this.scope;
    this.selection = null;
    this.stopPoll();
    this.syncSelection();
    void this.discover();
  }
  private selectedId(): string | null {
    const id = this.state.latest[this.project];
    return id && this.state.runs[id]?.owner?.project_root === this.project ? id : null;
  }
  selected(): RunData {
    const id = this.selectedId();
    return (id ? this.state.runs[id] : this.state.legacy[this.project]) ?? emptyRun();
  }
  private admit(id: string): boolean {
    if (!uuid(id)) return false;
    if (this.state.runs[id]) return true;
    const ids = Object.keys(this.state.runs);
    if (ids.length >= RUN_CAP) {
      const evicted = ids.find(
        (candidate) =>
          candidate !== this.selectedId() &&
          candidate !== this.state.foregroundId &&
          !activeStatus(this.state.runs[candidate].status) &&
          !this.owners.has(candidate) &&
          !this.telemetry.has(candidate),
      );
      if (!evicted) return false;
      const runs = { ...this.state.runs };
      delete runs[evicted];
      const latest = Object.fromEntries(
        Object.entries(this.state.latest).filter(([, runId]) => runId !== evicted),
      );
      this.statusVersions.delete(evicted);
      this.summaryVersions.delete(evicted);
      this.state = { ...this.state, runs, latest };
    }
    this.state = { ...this.state, runs: { ...this.state.runs, [id]: emptyRun() } };
    return true;
  }
  private patch(id: string, update: (run: RunData) => RunData) {
    if (!this.mounted || !this.state.runs[id]) return;
    this.state = { ...this.state, runs: { ...this.state.runs, [id]: update(this.state.runs[id]) } };
    this.emit();
  }
  private acceptOwner(owner: RunOwner): boolean {
    if (!this.mounted || !this.admit(owner.run_id)) return false;
    const known = this.state.runs[owner.run_id].owner;
    if (
      known &&
      (known.project_root !== owner.project_root ||
        known.target !== owner.target ||
        known.engine !== owner.engine ||
        known.kind !== owner.kind ||
        compareTimestamps(known.started_at, owner.started_at) !== 0)
    )
      return false;
    const run = this.state.runs[owner.run_id];
    // A terminal observation cannot be resurrected by a delayed Running read.
    const status =
      run.status && !activeStatus(run.status) && activeStatus(owner.status)
        ? run.status
        : owner.status;
    const accepted = { ...owner, status };
    const currentId = this.state.latest[owner.project_root];
    const advances = newer(owner, this.state.runs[currentId]?.owner ?? null);
    const legacy = { ...this.state.legacy };
    delete legacy[owner.project_root];
    this.state = {
      ...this.state,
      legacy,
      runs: {
        ...this.state.runs,
        [owner.run_id]: {
          ...run,
          owner: accepted,
          status,
          lastTarget: owner.target ?? "",
          lastEngine: owner.engine,
        },
      },
      latest: advances
        ? { ...this.state.latest, [owner.project_root]: owner.run_id }
        : this.state.latest,
    };
    this.emit();
    return true;
  }
  private ensureOwner(id: string, refresh = false): Promise<void> {
    const existing = this.owners.get(id);
    if (existing) return existing;
    if (
      !uuid(id) ||
      (!refresh && this.state.runs[id]?.owner) ||
      this.owners.size >= OWNER_REQUEST_CAP
    )
      return Promise.resolve();
    if (!this.admit(id)) return Promise.resolve();
    const epoch = this.epoch;
    const version = this.statusVersions.get(id) ?? 0;
    const request = this.transport
      .invoke<unknown>("run_owner", { runId: id })
      .then((value) => {
        if (!this.mounted || epoch !== this.epoch) return;
        const owner = parseOwner(value, id);
        if (!owner) return;
        if (version !== (this.statusVersions.get(id) ?? 0) && this.state.runs[id]?.status)
          owner.status = this.state.runs[id].status!;
        this.acceptOwner(owner);
      })
      .catch(() => {
        // Owner remains unknown; reconnect or later evidence retries the durable read.
      })
      .finally(() => {
        if (this.owners.get(id) === request) this.owners.delete(id);
      });
    this.owners.set(id, request);
    return request;
  }
  private async discover() {
    const project = this.project,
      generation = ++this.discovery,
      epoch = this.epoch;
    const summaryVersions = new Map(this.summaryVersions);
    if (!project || !this.mounted) return;
    try {
      const history = await this.transport.invoke<unknown>("run_history", { project });
      if (
        !this.mounted ||
        epoch !== this.epoch ||
        generation !== this.discovery ||
        !Array.isArray(history)
      )
        return;
      // History is newest first. Only the selected/latest record needs live hydration.
      const item = history.find((value) => record(value) && uuid(value.id));
      if (!record(item) || !uuid(item.id)) return;
      await this.ensureOwner(item.id, true);
      if (
        !this.mounted ||
        epoch !== this.epoch ||
        generation !== this.discovery ||
        this.state.runs[item.id]?.owner?.project_root !== project
      )
        return;
      if (
        !activeStatus(this.state.runs[item.id].status) &&
        (summaryVersions.get(item.id) ?? 0) === (this.summaryVersions.get(item.id) ?? 0) &&
        (!validStatus(item.status) || !activeStatus(item.status))
      )
        this.patch(item.id, (run) => ({ ...run, summary: parseSummary(item) }));
    } catch {
      // Discovery is best effort; the next connection, selection or terminal event retries it.
    }
  }
  private reconnect() {
    void this.discover();
    for (const [id, run] of Object.entries(this.state.runs)) {
      if (!run.owner) void this.ensureOwner(id);
    }
    const id = this.selectedId();
    if (id) {
      this.refreshTelemetry(id);
      void this.healthPages.hydrate(id);
    }
  }
  private syncSelection() {
    if (!this.mounted) return;
    const id = this.selectedId();
    if (this.selection !== id) {
      this.selection = id;
      ++this.scope;
      if (id) {
        this.healthPages.reset(id);
        this.refreshTelemetry(id);
        void this.healthPages.hydrate(id);
      }
    }
    const activeId = id && activeStatus(this.state.runs[id].status) ? id : null;
    if (activeId === this.pollId) return;
    this.stopPoll();
    if (!activeId) return;
    this.pollId = activeId;
    const scope = this.scope;
    this.poll = setInterval(() => {
      if (!this.mounted || scope !== this.scope || this.pollId !== activeId) return;
      this.refreshTelemetry(activeId);
      void this.ensureOwner(activeId, true).then(() => {
        if (
          this.mounted &&
          scope === this.scope &&
          !activeStatus(this.state.runs[activeId]?.status ?? null)
        )
          void this.discover();
      });
    }, 5000);
  }
  private stopPoll() {
    if (this.poll !== undefined) clearInterval(this.poll);
    this.poll = undefined;
    this.pollId = null;
  }
  private refreshTelemetry(id: string) {
    if (!this.mounted || !this.state.runs[id]) return;
    const existing = this.telemetry.get(id);
    if (existing) {
      existing.dirty = true;
      return;
    }
    if (this.telemetry.size >= OWNER_REQUEST_CAP) return;
    const token: ReadToken = { epoch: this.epoch, dirty: false };
    this.telemetry.set(id, token);
    void this.transport
      .invoke<unknown>("campaign_telemetry", { runId: id })
      .then((value) => {
        if (
          !this.mounted ||
          token.epoch !== this.epoch ||
          !record(value) ||
          value.schema_version !== 2 ||
          value.run_id !== id ||
          !timestamp(value.observed_at) ||
          count(value.throughput_sample_count) === null ||
          rate(value.throughput_sample_sum) === null
        )
          return;
        const observedAt = value.observed_at;
        this.patch(id, (run) =>
          run.observedAt && compareTimestamps(run.observedAt, observedAt) === 1
            ? run
            : {
                ...run,
                observedAt,
                stats: {
                  currentExecs: rate(value.current_execs),
                  meanExecs: rate(value.mean_execs),
                  peakExecs: rate(value.peak_execs),
                  edges: count(value.edges),
                  rawCrashSignals: run.stats.rawCrashSignals,
                },
              },
        );
      })
      .catch(() => {
        // Unavailable telemetry preserves the last authoritative snapshot, or Unknown.
      })
      .finally(() => {
        if (this.telemetry.get(id) !== token) return;
        this.telemetry.delete(id);
        if (
          this.mounted &&
          token.epoch === this.epoch &&
          token.dirty &&
          (id === this.selectedId() || id === this.state.foregroundId)
        )
          this.refreshTelemetry(id);
      });
  }
  loadOlderHealthEvents = async () => {
    const id = this.selectedId();
    const cursor = id ? this.state.runs[id].nextCursor : null;
    if (id && cursor) await this.healthPages.hydrate(id, cursor);
  };
  private progress(payload: unknown) {
    if (!record(payload) || !uuid(payload.run_id)) return;
    const id = payload.run_id;
    if (!this.state.runs[id] && this.owners.size >= OWNER_REQUEST_CAP) return;
    if (!this.admit(id)) return;
    void this.ensureOwner(id);
    if (payload.type === "LogLine" && typeof payload.data === "string")
      this.patch(id, (run) => ({
        ...run,
        log: [...run.log.slice(-(LOG_CAP - 1)), `  ${payload.data}`.slice(-LOG_LINE_CAP)],
      }));
    if (payload.type === "CrashesFound") {
      const delta = count(payload.data);
      if (delta !== null)
        this.patch(id, (run) => {
          const total = (run.stats.rawCrashSignals ?? 0) + delta;
          return count(total) === null
            ? run
            : { ...run, stats: { ...run.stats, rawCrashSignals: total } };
        });
    }
    if (payload.type === "ExecsPerSec" || payload.type === "EdgesCovered")
      this.refreshTelemetry(id);
  }
  private status(payload: unknown) {
    if (!record(payload) || !uuid(payload.run_id) || !validStatus(payload.status)) return;
    const id = payload.run_id,
      status = payload.status;
    if (!this.admit(id)) return;
    this.statusVersions.set(id, (this.statusVersions.get(id) ?? 0) + 1);
    this.patch(id, (run) => ({
      ...run,
      status,
      owner: run.owner ? { ...run.owner, status } : null,
    }));
    void this.ensureOwner(id);
    this.refreshTelemetry(id);
    if (!activeStatus(status) && id === this.selectedId()) void this.discover();
  }
  private rememberHealth(id: string) {
    this.notified.add(id);
    if (this.notified.size > RUN_CAP * HEALTH_CAP)
      this.notified.delete(this.notified.values().next().value!);
  }
  private liveHealth(payload: unknown) {
    if (!record(payload)) return;
    const owner = parseOwner(payload.owner);
    if (!owner) return;
    const event = parseHealth(payload.event, owner.run_id);
    if (!event) return;
    if (!this.acceptOwner(owner)) return;
    this.healthPages.merge(owner.run_id, [event]);
    if (event.severity === "error" && !this.notified.has(event.id)) {
      this.rememberHealth(event.id);
      this.toast({ title: event.condition, description: event.detail, variant: "error" });
    }
  }
  private async cancelId(id: string) {
    const invocation = this.invocation;
    try {
      await this.transport.invoke("cancel_run", { runId: id });
    } catch (error) {
      if (!this.mounted || invocation !== this.invocation || this.state.foregroundId !== id) return;
      this.state = { ...this.state, cancelling: false, requestError: errorMessage(error) };
      this.emit();
    }
  }
  cancelRun = async () => {
    if (this.state.requestState === "idle") return;
    this.cancelOnAdmission = true;
    this.state = { ...this.state, cancelling: true };
    this.emit();
    if (this.state.foregroundId) await this.cancelId(this.state.foregroundId);
  };
  private async launch(
    command: string,
    args: Record<string, unknown>,
    engine: string,
  ): Promise<number> {
    if (this.state.requestState !== "idle") throw new Error("A foreground run is already active");
    const generation = ++this.invocation;
    this.cancelOnAdmission = false;
    this.state = {
      ...this.state,
      requestState: "pending",
      requestError: null,
      foregroundId: null,
      cancelling: false,
    };
    this.setEngine(engine);
    this.emit();
    let admittedId: string | null = null;
    try {
      const result = await this.transport.invoke<unknown>(command, args, {
        onRunStarted: (id) => {
          if (!this.mounted || generation !== this.invocation || !uuid(id)) return;
          admittedId = id;
          this.state = { ...this.state, foregroundId: id, requestState: "admitted" };
          void this.ensureOwner(id);
          this.emit();
          if (this.cancelOnAdmission) void this.cancelId(id);
        },
      });
      if (!record(result) || !uuid(result.run_id) || (admittedId && result.run_id !== admittedId))
        throw new Error("Invalid run result identity");
      const summary = parseSummary(result);
      if (!summary || summary.edges === null || summary.execs === null)
        throw new Error("Invalid run result metrics");
      if (this.mounted && generation === this.invocation) {
        void this.ensureOwner(result.run_id);
        if (this.state.runs[result.run_id]) {
          this.summaryVersions.set(
            result.run_id,
            (this.summaryVersions.get(result.run_id) ?? 0) + 1,
          );
          this.patch(result.run_id, (run) => ({ ...run, summary }));
          this.refreshTelemetry(result.run_id);
        }
      }
      return summary.crashes;
    } catch (error) {
      if (this.mounted && generation === this.invocation) {
        this.state = { ...this.state, requestError: errorMessage(error) };
        this.emit();
      }
      throw error;
    } finally {
      if (this.mounted && generation === this.invocation) {
        this.state = { ...this.state, foregroundId: null, requestState: "idle", cancelling: false };
        this.setEngine(null);
        this.emit();
      }
    }
  }
  runFuzzer: RunOutputValue["runFuzzer"] = (params) =>
    this.launch("run_fuzzer", params, params.engine);
  replayRun: RunOutputValue["replayRun"] = (review) =>
    this.launch("replay_run", { runId: review.run_id, project: review.project, review }, review.engine);
  runSyzkaller: RunOutputValue["runSyzkaller"] = (opts) =>
    this.launch("run_syzkaller", { opts }, "syzkaller");
  clear = () => {
    const id = this.selectedId();
    if (id) this.patch(id, (run) => ({ ...run, log: [] }));
  };
}
