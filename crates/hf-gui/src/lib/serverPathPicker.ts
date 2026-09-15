import { createElement } from "react";
import { createRoot } from "react-dom/client";
import { I18nProvider } from "../i18n";
import { ServerPathDialog, type PathKind } from "../components/ServerPathPicker";

export function pickServerPath(kind: PathKind, title?: string): Promise<string | null> {
  const host = document.createElement("div");
  const previousFocus = document.activeElement;
  document.body.append(host);
  const root = createRoot(host);
  return new Promise(resolve => {
    const finish = (value: string | null) => {
      queueMicrotask(() => { root.unmount(); host.remove(); if (previousFocus instanceof HTMLElement) previousFocus.focus(); resolve(value); });
    };
    root.render(createElement(I18nProvider, null, createElement(ServerPathDialog, { kind, title, onFinish: finish })));
  });
}
