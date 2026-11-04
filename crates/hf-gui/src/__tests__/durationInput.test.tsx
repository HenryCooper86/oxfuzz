// @vitest-environment jsdom
import { act, useState } from "react";
import { createRoot } from "react-dom/client";
import { expect, it, vi } from "vitest";
import { DurationInput } from "../components/ui/DurationInput";
import { formatDuration, splitDuration, toSeconds } from "../lib/duration";
import { I18nProvider } from "../i18n";

it("formats seconds the way people say them", () => {
  expect(formatDuration(45)).toBe("45 s");
  expect(formatDuration(60)).toBe("1 min");
  expect(formatDuration(90)).toBe("1 min 30 s");
  expect(formatDuration(3600)).toBe("1 h");
  expect(formatDuration(5400)).toBe("1 h 30 min");
  expect(formatDuration(7200)).toBe("2 h");
});

it("shows a stored value in the largest whole unit and converts back to seconds", () => {
  expect(splitDuration("3600")).toEqual({ amount: "1", unit: "h" });
  expect(splitDuration("120")).toEqual({ amount: "2", unit: "m" });
  expect(splitDuration("90")).toEqual({ amount: "90", unit: "s" });
  expect(splitDuration("")).toEqual({ amount: "", unit: "s" });
  expect(toSeconds("2", "h")).toBe("7200");
  expect(toSeconds("1.5", "m")).toBe("90");
  expect(toSeconds("", "m")).toBe("");
  expect(toSeconds("abc", "m")).toBe("abc");
});

function Harness({ initial, onSeconds }: { initial: string; onSeconds: (value: string) => void }) {
  const [seconds, setSeconds] = useState(initial);
  return <DurationInput ariaLabel="Duration" seconds={seconds} onChange={(value) => { setSeconds(value); onSeconds(value); }} />;
}

it("edits the amount in the chosen unit and reports seconds", async () => {
  vi.stubGlobal("IS_REACT_ACT_ENVIRONMENT", true);
  const host = document.createElement("div"); document.body.append(host); const root = createRoot(host);
  const onSeconds = vi.fn();
  try {
    await act(async () => root.render(<I18nProvider><Harness initial="3600" onSeconds={onSeconds} /></I18nProvider>));
    const number = host.querySelector("input")!;
    expect(number.value).toBe("1");
    expect(host.textContent).toContain("hours");
    await act(async () => {
      Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value")!.set!.call(number, "2");
      number.dispatchEvent(new Event("input", { bubbles: true }));
    });
    expect(onSeconds).toHaveBeenLastCalledWith("7200");
    expect(number.value).toBe("2");
  } finally { await act(async () => root.unmount()); host.remove(); vi.unstubAllGlobals(); }
});

it("keeps what the user is typing when the owner ignores an invalid value", async () => {
  vi.stubGlobal("IS_REACT_ACT_ENVIRONMENT", true);
  const host = document.createElement("div"); document.body.append(host); const root = createRoot(host);
  // The owner only accepts whole positive seconds, like Settings does.
  function Owner() {
    const [seconds, setSeconds] = useState("3600");
    return <DurationInput ariaLabel="Duration" seconds={seconds} onChange={(value) => { if (Number(value) >= 1) setSeconds(value); }} />;
  }
  const type = async (input: HTMLInputElement, value: string) => act(async () => {
    Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value")!.set!.call(input, value);
    input.dispatchEvent(new Event("input", { bubbles: true }));
  });
  try {
    await act(async () => root.render(<I18nProvider><Owner /></I18nProvider>));
    const number = host.querySelector("input")!;
    await type(number, "");
    expect(number.value).toBe("");
    expect(host.textContent).toContain("hours");
    await type(number, "3");
    expect(number.value).toBe("3");
    expect(host.textContent).toContain("hours");
  } finally { await act(async () => root.unmount()); host.remove(); vi.unstubAllGlobals(); }
});
