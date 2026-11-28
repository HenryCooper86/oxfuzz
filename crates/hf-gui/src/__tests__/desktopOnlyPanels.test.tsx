// @vitest-environment jsdom
import { act } from "react";
import { createRoot } from "react-dom/client";
import { expect, it, vi } from "vitest";
import { RemoteArmPanel } from "../components/RemoteArmPanel";
import { RestServerPanel } from "../components/RestServerPanel";
import { I18nProvider } from "../i18n";

const invoke = vi.hoisted(() => vi.fn());
vi.mock("../lib", async (original) => ({ ...(await original<typeof import("../lib")>()), getTransport: () => ({ invoke }) }));
vi.mock("../lib/transport", async (original) => ({ ...(await original<typeof import("../lib/transport")>()), isTauriEnvironment: () => false }));

it("names the REST server and remote arming as desktop features in the browser, without calling them", async () => {
  // In the browser both panels offered controls whose commands do not exist
  // there ("Unsupported command in web mode").
  vi.stubGlobal("IS_REACT_ACT_ENVIRONMENT", true);
  const host = document.createElement("div"); document.body.append(host); const root = createRoot(host);
  try {
    await act(async () => root.render(<I18nProvider><RestServerPanel project="/p" /><RemoteArmPanel /></I18nProvider>));
    expect(host.querySelectorAll("button")).toHaveLength(0);
    expect(host.textContent).toContain("REST server");
    expect(host.textContent).toContain("Another server");
    expect(host.textContent?.match(/desktop app/g)).toHaveLength(2);
    expect(invoke).not.toHaveBeenCalled();
  } finally { await act(async () => root.unmount()); host.remove(); vi.unstubAllGlobals(); }
});
