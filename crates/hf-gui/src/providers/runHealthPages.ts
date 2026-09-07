import type { Transport } from "../lib/transport";
import {
  errorMessage,
  HEALTH_CAP,
  HEALTH_REQUEST_CAP,
  type HealthItem,
  type RunData,
} from "./runOutputState";
import { parseHealth, record, uuid } from "./runOutputValidation";

interface HealthPageContext {
  active: () => boolean;
  selectedId: () => string | null;
  scope: () => number;
  epoch: () => number;
  patch: (id: string, update: (run: RunData) => RunData) => void;
  remember: (id: string) => void;
}

/** Bounded, silent retained-page hydration for the selected run. */
export class RunHealthPages {
  private reads = new Map<string, { promise: Promise<void>; scope: number; refresh: boolean }>();

  constructor(
    private transport: Transport,
    private context: HealthPageContext,
  ) {}

  clear() {
    this.reads.clear();
  }
  reset(id: string) {
    this.context.patch(id, (run) => ({
      ...run,
      nextCursor: undefined,
      healthLoading: false,
      healthError: null,
    }));
  }
  merge(id: string, events: HealthItem[]): boolean {
    let added = false;
    this.context.patch(id, (run) => {
      const merged = new Map(run.healthEvents.map((event) => [event.id, event]));
      for (const event of events) {
        if (!merged.has(event.id)) added = true;
        merged.set(event.id, event);
      }
      return { ...run, healthEvents: [...merged.values()].slice(-HEALTH_CAP) };
    });
    return added;
  }
  hydrate(id: string, cursor?: string): Promise<void> {
    if (!this.context.active() || id !== this.context.selectedId()) return Promise.resolve();
    const existing = this.reads.get(id);
    if (existing) {
      if (!cursor || existing.scope !== this.context.scope()) existing.refresh = true;
      return existing.promise;
    }
    if (this.reads.size >= HEALTH_REQUEST_CAP) {
      this.context.patch(id, (run) => ({
        ...run,
        healthLoading: false,
        healthError: "run.healthBusy",
      }));
      return Promise.resolve();
    }
    const scope = this.context.scope(),
      epoch = this.context.epoch();
    this.context.patch(id, (run) => ({ ...run, healthLoading: true, healthError: null }));
    const request = { scope, refresh: false, promise: Promise.resolve() };
    request.promise = this.transport
      .invoke<unknown>("campaign_health_events", { runId: id, cursor, limit: 100 })
      .then((value) => {
        if (
          !this.context.active() ||
          scope !== this.context.scope() ||
          epoch !== this.context.epoch() ||
          id !== this.context.selectedId()
        )
          return;
        if (
          !record(value) ||
          !Array.isArray(value.events) ||
          (value.next_cursor !== null && !uuid(value.next_cursor))
        )
          throw new Error("Invalid retained health page");
        const events = value.events.map((event) => parseHealth(event, id));
        if (events.some((event) => event === null))
          throw new Error("Invalid retained health event");
        const accepted = events.filter((event): event is HealthItem => event !== null);
        for (const event of accepted) this.context.remember(event.id);
        const added = this.merge(id, accepted);
        const nextCursor = value.next_cursor as string | null;
        this.context.patch(id, (run) => ({
          ...run,
          nextCursor: cursor || added || run.nextCursor === undefined ? nextCursor : run.nextCursor,
          healthLoading: false,
          healthError: null,
        }));
      })
      .catch((error: unknown) => {
        if (
          this.context.active() &&
          scope === this.context.scope() &&
          epoch === this.context.epoch()
        )
          this.context.patch(id, (run) => ({
            ...run,
            healthLoading: false,
            healthError: errorMessage(error),
          }));
      })
      .finally(() => {
        if (this.reads.get(id) !== request) return;
        this.reads.delete(id);
        if (
          request.refresh &&
          this.context.active() &&
          epoch === this.context.epoch() &&
          id === this.context.selectedId()
        )
          void this.hydrate(id);
      });
    this.reads.set(id, request);
    return request.promise;
  }
}
