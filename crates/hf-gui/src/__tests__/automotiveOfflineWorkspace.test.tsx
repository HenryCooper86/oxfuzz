// @vitest-environment jsdom
import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { AutomotiveOfflineWorkspace } from "../components/AutomotiveOfflineWorkspace";
import { AutomotiveSignalGraph } from "../components/AutomotiveSignalGraph";
import { I18nProvider } from "../i18n";
import type { CaptureImport, OfflineFrameView } from "../lib/automotive";

const io = vi.hoisted(() => ({ pick: vi.fn(), invoke: vi.fn() }));
vi.mock("../lib", () => ({
  isTauriEnvironment: () => true,
  pickFile: io.pick,
  getTransport: () => ({ invoke: io.invoke }),
}));

const frame = (id: number, value: number, extra: Partial<OfflineFrameView> = {}): OfflineFrameView => ({
  timestamp_micros: value * 1_000_000, channel: "can0", id, extended: false,
  fd: false, kind: "data", data_hex: "01", direction: null, message: "Sensor",
  signals: [{ name: "Speed", value, unit: "km/h", label: null }], ...extra,
});
const capture: CaptureImport = {
  format: "candump", frame_count: 2, truncated: false, dbc_message_count: 1,
  unique_ids: 1, duration_micros: 1_000_000, frames_per_second: 2,
  frames: [frame(0x123, 10), frame(0x123, 20)], per_id: [], change_maps: [],
  protocol_states: { completed_pdus: 0, malformed_frames: 0, unique_states: [], transitions: [] },
};
let host: HTMLDivElement;
let root: Root;
const button = (label: string) => [...host.querySelectorAll("button")].find((item) => item.textContent?.trim() === label)!;
async function click(label: string) {
  expect(button(label), `button ${label}`).toBeDefined();
  await act(async () => button(label).click());
}
async function choose(label: string, path: string) {
  io.pick.mockResolvedValueOnce(path);
  await click(label);
}
async function mount() {
  await act(async () => root.render(<I18nProvider><AutomotiveOfflineWorkspace /></I18nProvider>));
  await choose("Select capture", "/fixtures/first.log");
}
async function analyze() {
  io.invoke.mockResolvedValueOnce(capture);
  await click("Analyze");
  expect(host.querySelector("table")?.textContent).toContain("Sensor");
}
beforeEach(() => {
  vi.stubGlobal("IS_REACT_ACT_ENVIRONMENT", true);
  localStorage.clear();
  io.pick.mockReset(); io.invoke.mockReset();
  host = document.createElement("div"); document.body.append(host); root = createRoot(host);
});
afterEach(async () => {
  await act(async () => root.unmount()); host.remove(); vi.unstubAllGlobals();
});

it("clears decoded frames when a different capture is selected", async () => {
  await mount(); await analyze();
  await choose("first.log", "/fixtures/second.log");
  expect(host.querySelector("table")).toBeNull();
  expect(host.querySelector('svg[role="img"]')).toBeNull();
});

it("clears comparison results when the second capture changes", async () => {
  await mount();
  await choose("Select second capture", "/fixtures/second.log");
  io.invoke.mockResolvedValueOnce({ only_in_first: [{ id: 0x123, extended: false }], only_in_second: [], changed: [] });
  await click("Compare");
  expect(host.textContent).toContain("0x123");
  await choose("second.log", "/fixtures/third.log");
  expect(host.textContent).not.toContain("0x123");
});

it("clears decoded frames when the DBC changes", async () => {
  await mount(); await analyze();
  await choose("Load DBC", "/fixtures/new.dbc");
  expect(host.querySelector("table")).toBeNull();
});

it("does not leave a successful decode visible after a failed retry", async () => {
  await mount(); await analyze();
  io.invoke.mockRejectedValueOnce(new Error("malformed capture"));
  await click("Analyze");
  expect(host.querySelector('[role="alert"]')?.textContent).toContain("malformed capture");
  expect(host.querySelector("table")).toBeNull();
});

it("discards a late decode after the selected capture changes", async () => {
  await mount();
  let finish!: (result: CaptureImport) => void;
  io.invoke.mockReturnValueOnce(new Promise<CaptureImport>((resolve) => { finish = resolve; }));
  await click("Analyze");
  await choose("first.log", "/fixtures/second.log");
  await act(async () => finish(capture));
  expect(host.querySelector("table")).toBeNull();
  expect(button("Analyze").disabled).toBe(false);
});

it("plots same-named signals separately by channel and CAN frame identity", async () => {
  const frames = [frame(0x123, 10), frame(0x124, 100), frame(0x123, 20), frame(0x124, 200),
    frame(0x123, 30, { extended: true }), frame(0x123, 40, { channel: "can1" }), frame(0x123, 50, { fd: true })];
  await act(async () => root.render(<I18nProvider><AutomotiveSignalGraph frames={frames} /></I18nProvider>));
  const choices = [...host.querySelectorAll("button")];
  expect(choices).toHaveLength(5);
  expect(new Set(choices.map((item) => item.textContent)).size).toBe(5);
  expect(choices[0].textContent).toContain("0x123");
  const line = host.querySelector('svg path[stroke-linejoin="round"]')!;
  expect(line.getAttribute("d")?.match(/[ML]/g)).toHaveLength(2);
});

it("clears decoded frames when the capture format changes", async () => {
  const previousScroll = Element.prototype.scrollIntoView;
  Element.prototype.scrollIntoView = () => {};
  try {
    await mount(); await analyze();
    await act(async () => host.querySelector<HTMLElement>('[role="combobox"]')!.click());
    const option = [...document.querySelectorAll<HTMLElement>('[role="option"]')].find((item) => item.textContent === "Vector ASC")!;
    await act(async () => option.click());
    expect(host.querySelector("table")).toBeNull();
  } finally {
    Element.prototype.scrollIntoView = previousScroll;
  }
});

it("discards late comparison failures after changing a capture", async () => {
  await mount(); await choose("Select second capture", "/fixtures/second.log");
  let fail!: (error: Error) => void;
  io.invoke.mockReturnValueOnce(new Promise((_, reject) => { fail = reject; }));
  await click("Compare");
  await choose("second.log", "/fixtures/third.log");
  await act(async () => fail(new Error("old capture is invalid")));
  expect(host.querySelector('[role="alert"]')).toBeNull();
});

it("selects a signal when a new capture replaces the previous graph", async () => {
  const render = (frames: OfflineFrameView[]) => act(async () => root.render(<I18nProvider><AutomotiveSignalGraph frames={frames} /></I18nProvider>));
  await render([frame(0x123, 10)]);
  await render([frame(0x456, 5, { signals: [{ name: "Temperature", value: 5, unit: "C", label: null }] })]);
  expect(host.querySelector('svg path[stroke-linejoin="round"]')).not.toBeNull();
  expect(host.textContent).toContain("Temperature");
});

it("renders constant signal values without duplicate React keys", async () => {
  const errors = vi.spyOn(console, "error");
  try {
    await act(async () => root.render(<I18nProvider><AutomotiveSignalGraph frames={[frame(0x123, 10)]} /></I18nProvider>));
    expect(host.querySelectorAll('svg[role="img"] line')).toHaveLength(3);
    expect(errors.mock.calls.filter((args) => String(args[0]).includes("same key"))).toHaveLength(0);
  } finally {
    errors.mockRestore();
  }
});
