// @vitest-environment jsdom
import { afterEach, expect, it, vi } from "vitest";
import { RunOutputController } from "../providers/runOutputController";
import type { Transport } from "../lib/transport";

afterEach(() => { vi.useRealTimers(); localStorage.clear(); });

it("paces a crash-output burst, retains the bounded tail, and publishes completion immediately", async () => {
  vi.useFakeTimers();
  const callbacks = new Map<string, (event: { payload: unknown }) => void>();
  const transport = {
    invoke: vi.fn(async () => null),
    listen: vi.fn(async (name, callback) => { callbacks.set(name, callback); return () => callbacks.delete(name); }),
  } as Transport;
  const controller = new RunOutputController(transport);
  const stop = controller.start();
  await Promise.resolve();
  const notify = vi.fn();
  controller.subscribe(notify);
  const id = "00000000-0000-4000-8000-000000000001";
  const progress = (type: string, data: unknown) => callbacks.get("run:progress")!({ payload: { run_id: id, type, data } });
  for (let i = 0; i < 10_000; i++) {
    progress("LogLine", `crash ${i}`);
    progress("CrashesFound", 1);
  }
  expect(notify).not.toHaveBeenCalled();
  await vi.advanceTimersByTimeAsync(100);
  expect(notify).toHaveBeenCalledTimes(1);
  expect(controller.state.runs[id].log).toHaveLength(600);
  expect(controller.state.runs[id].log.at(-1)).toBe("  crash 9999");
  expect(controller.state.runs[id].stats.rawCrashSignals).toBe(10_000);
  progress("LogLine", "last line");
  callbacks.get("run:status")!({ payload: { run_id: id, status: "Done" } });
  expect(controller.state.runs[id].status).toBe("Done");
  expect(controller.state.runs[id].log.at(-1)).toBe("  last line");
  expect(notify).toHaveBeenCalledTimes(2);
  progress("LogLine", "queued before unmount");
  stop();
  await vi.advanceTimersByTimeAsync(100);
  expect(notify).toHaveBeenCalledTimes(2);
});
