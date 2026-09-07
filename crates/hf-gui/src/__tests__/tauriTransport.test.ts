import { beforeEach, describe, expect, it, vi } from "vitest";
import { createTauriTransport } from "../lib/tauriTransport";

const core = vi.hoisted(() => ({
  invoke: vi.fn(),
}));

vi.mock("@tauri-apps/api/core", () => ({
  Channel: class<T> {
    onmessage: (message: T) => void;

    constructor(onmessage?: (message: T) => void) {
      this.onmessage = onmessage ?? (() => undefined);
    }
  },
  invoke: core.invoke,
}));

describe("tauri transport run admission", () => {
  beforeEach(() => {
    core.invoke.mockReset();
  });

  it("isolates request-scoped admission channels for both native launch commands", async () => {
    const completions = new Map<string, (value: unknown) => void>();
    core.invoke.mockImplementation((command: string) =>
      new Promise((resolve) => completions.set(command, resolve))
    );
    const fuzzerStarted: string[] = [];
    const syzkallerStarted: string[] = [];
    const transport = createTauriTransport();

    const fuzzer = transport.invoke(
      "run_fuzzer",
      { project: "/tmp/project" },
      { onRunStarted: (runId) => fuzzerStarted.push(runId) },
    );
    await vi.waitFor(() => expect(core.invoke).toHaveBeenCalledTimes(1));
    const syzkaller = transport.invoke(
      "run_syzkaller",
      { opts: { project: "/tmp/project" } },
      { onRunStarted: (runId) => syzkallerStarted.push(runId) },
    );
    await vi.waitFor(() => expect(core.invoke).toHaveBeenCalledTimes(2));

    const fuzzerArgs = core.invoke.mock.calls.find(([command]) => command === "run_fuzzer")?.[1];
    const syzkallerArgs = core.invoke.mock.calls.find(([command]) => command === "run_syzkaller")?.[1];
    const fuzzerChannel = fuzzerArgs?.onRunStarted as { onmessage: (id: string) => void };
    const syzkallerChannel = syzkallerArgs?.onRunStarted as { onmessage: (id: string) => void };

    expect(fuzzerStarted).toEqual([]);
    expect(syzkallerStarted).toEqual([]);
    fuzzerChannel.onmessage("fuzzer-run-id");
    expect(fuzzerStarted).toEqual(["fuzzer-run-id"]);
    expect(syzkallerStarted).toEqual([]);
    syzkallerChannel.onmessage("syzkaller-run-id");
    expect(syzkallerStarted).toEqual(["syzkaller-run-id"]);

    completions.get("run_fuzzer")?.({ run_id: "fuzzer-run-id" });
    completions.get("run_syzkaller")?.({ run_id: "syzkaller-run-id" });
    await Promise.all([fuzzer, syzkaller]);
  });

  it("does not report admission when native invocation fails before channel delivery", async () => {
    core.invoke.mockRejectedValue(new Error("admission rejected"));
    const admitted: string[] = [];

    await expect(
      createTauriTransport().invoke(
        "run_fuzzer",
        {},
        { onRunStarted: (runId) => admitted.push(runId) },
      ),
    ).rejects.toThrow("admission rejected");
    expect(admitted).toEqual([]);
  });

  it("leaves direct native launch callers without an admission channel", async () => {
    core.invoke.mockResolvedValue({ run_id: "terminal-run" });

    await createTauriTransport().invoke("run_fuzzer", { project: "/tmp/project" });

    expect(core.invoke).toHaveBeenCalledWith("run_fuzzer", { project: "/tmp/project" });
  });
});
