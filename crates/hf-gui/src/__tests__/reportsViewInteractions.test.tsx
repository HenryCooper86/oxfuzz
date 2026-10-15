// @vitest-environment jsdom

import { StrictMode, act } from "react";
import { createRoot } from "react-dom/client";
import type { Root } from "react-dom/client";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { I18nContext } from "../i18nContext";
import { ConfirmContext, type ConfirmFn } from "../providers/confirm";
import { ReportsView } from "../views/ReportsView";
import type { ReportDraft } from "../types";
import type * as LibModule from "../lib";

const mocks = vi.hoisted(() => ({
  invoke: vi.fn(),
  desktop: false,
  listeners: new Set<() => void>(),
}));

vi.mock("../lib", async (importOriginal) => ({
  ...(await importOriginal<typeof LibModule>()),
  getTransport: () => ({ invoke: mocks.invoke }),
  isTauriEnvironment: () => mocks.desktop,
  emitDataChanged: () => {
    for (const listener of mocks.listeners) listener();
  },
  onDataChanged: (listener: () => void) => {
    mocks.listeners.add(listener);
    return () => {
      mocks.listeners.delete(listener);
    };
  },
}));

(globalThis as typeof globalThis & { IS_REACT_ACT_ENVIRONMENT: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

const draft: ReportDraft = {
  id: "draft-1",
  title: "Parser findings",
  project: "/workspace/project",
  target: "src/parser.c::parse",
  status: "Reviewed",
  updated_at: "2026-10-01T00:00:00Z",
  content: "# Parser findings",
};

function deferred<T>() {
  let resolve!: (value: T) => void;
  let reject!: (reason: unknown) => void;
  const promise = new Promise<T>((yes, no) => {
    resolve = yes;
    reject = no;
  });
  return { promise, resolve, reject };
}

function translate(key: string, params?: Record<string, string | number>) {
  // The real dictionary renders the offered formats inside this description;
  // echo the params so the assertion observes actual rendered output.
  if (key === "gui.reportDescription" && params) return `Report formats: ${params.formats}`;
  if (!params) return key;
  return Object.entries(params).reduce(
    (text, [name, value]) => text.replace(`{${name}}`, String(value)),
    key,
  );
}

function Providers({ confirm, children }: { confirm?: ConfirmFn; children: React.ReactNode }) {
  return (
    <I18nContext.Provider value={{ locale: "en", setLocale: () => undefined, t: translate }}>
      <ConfirmContext.Provider value={confirm ?? (async () => true)}>
        {children}
      </ConfirmContext.Provider>
    </I18nContext.Provider>
  );
}

async function flush() {
  await act(async () => {
    await Promise.resolve();
  });
}

function deleteButton(container: HTMLElement): HTMLButtonElement {
  const match = container.querySelector<HTMLButtonElement>('[aria-label="reports.deleteReport"]');
  if (!match) throw new Error(`delete button not found: ${container.textContent}`);
  return match;
}

describe("ReportsView interactions", () => {
  let container: HTMLDivElement;
  let root: Root;

  beforeEach(() => {
    mocks.invoke.mockReset();
    mocks.desktop = false;
    mocks.listeners.clear();
    container = document.createElement("div");
    document.body.append(container);
    root = createRoot(container);
  });

  afterEach(async () => {
    await act(async () => root.unmount());
    container.remove();
  });

  it("offers only formats the browser can actually export", async () => {
    mocks.invoke.mockImplementation((command: string) => {
      if (command === "list_report_drafts") return Promise.resolve([draft]);
      if (command === "report_formats") return Promise.resolve(["md", "pdf"]);
      throw new Error(`unexpected ${command}`);
    });

    await act(async () => root.render(<StrictMode><Providers><ReportsView /></Providers></StrictMode>));
    await flush();

    // Browser sessions can only download the saved Markdown (the web layer has
    // no report download endpoint), so the advertised list must not promise
    // PDF or HTML exports that could only report "desktop only".
    expect(container.textContent).toContain("Report formats: MD");
    expect(container.textContent).not.toContain("PDF");
    expect(container.textContent).not.toContain("HTML");
  });

  it("offers the service-supported formats on desktop", async () => {
    mocks.desktop = true;
    mocks.invoke.mockImplementation((command: string) => {
      if (command === "list_report_drafts") return Promise.resolve([draft]);
      if (command === "report_formats") return Promise.resolve(["md", "html"]);
      throw new Error(`unexpected ${command}`);
    });

    await act(async () => root.render(<StrictMode><Providers><ReportsView /></Providers></StrictMode>));
    await flush();

    expect(container.textContent).toContain("Report formats: MD / HTML");
  });

  it("does not queue a duplicate destructive delete for one report", async () => {
    const confirm = vi.fn<ConfirmFn>(async () => true);
    const removal = deferred<unknown>();
    let deletes = 0;
    mocks.invoke.mockImplementation((command: string) => {
      if (command === "list_report_drafts") return Promise.resolve(deletes === 0 ? [draft] : []);
      if (command === "report_formats") return Promise.resolve(["md", "html"]);
      if (command === "delete_report_draft") {
        deletes += 1;
        // A second delete of the same draft reaches the service after the row
        // is already gone, so it fails and would surface a misleading error.
        return deletes === 1 ? removal.promise : Promise.reject(new Error("draft not found"));
      }
      throw new Error(`unexpected ${command}`);
    });

    // Two real instances share the data-change channel the way the Reports
    // page and the Workbench reports tab do.
    await act(async () => root.render(
      <StrictMode>
        <Providers confirm={confirm}>
          <ReportsView />
          <ReportsView />
        </Providers>
      </StrictMode>,
    ));
    await flush();

    const remove = deleteButton(container);
    await act(async () => {
      remove.click();
      remove.click();
    });
    expect(confirm).toHaveBeenCalledTimes(1);
    expect(deletes).toBe(1);

    await act(async () => removal.resolve(undefined));
    await flush();
    // The deleting view reloads itself; the sibling must also drop the draft
    // through the data-change notification, not keep a stale listing.
    expect(container.textContent).not.toContain("Parser findings");
    expect(container.textContent).not.toContain("reports.deleteFailed");
  });

  it("keeps publication single-flight across saved reports", async () => {
    const publication = deferred<unknown>();
    let attempts = 0;
    mocks.invoke.mockImplementation((command: string) => {
      if (command === "list_report_drafts") return Promise.resolve([
        { ...draft, project: "<redacted-path>" },
        { ...draft, id: "draft-2", title: "Other findings", project: "<redacted-path>" },
      ]);
      if (command === "push_report_to_defectdojo") {
        attempts += 1;
        return attempts === 1 ? publication.promise : Promise.reject(new Error("duplicate publication"));
      }
      throw new Error(`unexpected ${command}`);
    });
    await act(async () => root.render(<StrictMode><Providers><ReportsView /></Providers></StrictMode>));
    await flush();
    const buttons = [...container.querySelectorAll("button")].filter((button) => button.textContent === "DefectDojo");
    expect(buttons).toHaveLength(2);
    await act(async () => {
      buttons[0].click();
      buttons[0].click();
    });
    expect(container.textContent).not.toContain("reports.pushFailed");
    expect(buttons.every((button) => button.disabled)).toBe(true);
    await act(async () => publication.resolve({ findings_pushed: 2, reimported: false, url: null }));
    expect(container.textContent).toContain("reports.pushed");
    expect(buttons.every((button) => !button.disabled)).toBe(true);
  });
});
