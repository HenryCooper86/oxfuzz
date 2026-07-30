import { describe, expect, it } from "vitest";
import {
  acknowledgeRecoveryWithRefresh,
  createLatestRefresh,
  initialRecoveryLoadState,
  recoveryLoadReducer,
} from "../lib/scheduleRecovery";

interface Deferred<T> {
  promise: Promise<T>;
  resolve: (value: T) => void;
}

function deferred<T>(): Deferred<T> {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((next) => {
    resolve = next;
  });
  return { promise, resolve };
}

describe("acknowledgeRecoveryWithRefresh", () => {
  it("does nothing when confirmation is declined", async () => {
    const calls: string[] = [];
    const applied = await acknowledgeRecoveryWithRefresh({
      occurrenceId: "occ-1",
      confirm: async () => false,
      acknowledge: async () => calls.push("acknowledge"),
      refresh: async () => calls.push("refresh"),
    });
    expect(applied).toBe(false);
    expect(calls).toEqual([]);
  });

  it("acknowledges before refreshing all automation state", async () => {
    const calls: string[] = [];
    const applied = await acknowledgeRecoveryWithRefresh({
      occurrenceId: "occ-1",
      confirm: async () => true,
      acknowledge: async (occurrenceId) =>
        calls.push(`acknowledge:${occurrenceId}`),
      refresh: async () => calls.push("refresh"),
    });
    expect(applied).toBe(true);
    expect(calls).toEqual(["acknowledge:occ-1", "refresh"]);
  });

  it("keeps the post-acknowledgement snapshot when an older poll resolves last", async () => {
    interface Snapshot {
      campaigns: string[];
      history: string[];
      recoveries: string[];
    }

    const preAck = deferred<Snapshot>();
    const postAck = deferred<Snapshot>();
    const loads = [preAck.promise, postAck.promise];
    let snapshot: Snapshot = {
      campaigns: ["initial-campaign"],
      history: ["initial-history"],
      recoveries: ["initial-recovery"],
    };
    const latestRefresh = createLatestRefresh({
      load: async () => loads.shift() ?? Promise.reject(new Error("unexpected load")),
      commit: (next) => {
        snapshot = next;
      },
    });
    latestRefresh.activate();

    const pendingPoll = latestRefresh.refresh();
    const acknowledgement = acknowledgeRecoveryWithRefresh({
      occurrenceId: "occ-1",
      confirm: async () => true,
      acknowledge: async () => undefined,
      refresh: latestRefresh.refresh,
    });

    postAck.resolve({
      campaigns: ["post-ack-campaign"],
      history: ["post-ack-history"],
      recoveries: [],
    });
    expect(await acknowledgement).toBe(true);

    preAck.resolve({
      campaigns: ["pre-ack-campaign"],
      history: ["pre-ack-history"],
      recoveries: ["occ-1"],
    });
    expect(await pendingPoll).toBe(false);
    expect(snapshot).toEqual({
      campaigns: ["post-ack-campaign"],
      history: ["post-ack-history"],
      recoveries: [],
    });
  });

  it("ignores an in-flight refresh after the consumer is deactivated", async () => {
    const pending = deferred<string>();
    let committed = "initial";
    const latestRefresh = createLatestRefresh({
      load: async () => pending.promise,
      commit: (next) => {
        committed = next;
      },
    });
    latestRefresh.activate();

    const inFlight = latestRefresh.refresh();
    latestRefresh.deactivate();
    pending.resolve("late");

    expect(await inFlight).toBe(false);
    expect(committed).toBe("initial");
  });
});

describe("recoveryLoadReducer", () => {
  it("starts in a distinct loading state", () => {
    expect(initialRecoveryLoadState).toEqual({
      loading: true,
      error: false,
    });
  });

  it("clears a transient error after a successful refresh", () => {
    const failed = recoveryLoadReducer(initialRecoveryLoadState, "error");
    expect(failed).toEqual({ loading: false, error: true });

    const retrying = recoveryLoadReducer(failed, "start");
    expect(retrying).toEqual({ loading: true, error: true });

    expect(recoveryLoadReducer(retrying, "success")).toEqual({
      loading: false,
      error: false,
    });
  });
});
