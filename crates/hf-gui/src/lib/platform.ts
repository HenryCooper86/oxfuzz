// Platform abstraction for file dialogs.

import { getTransport } from "./index";
import { isTauriEnvironment } from "./transport";

/// Open a native file picker dialog and return the selected file path.
export async function pickFile(title?: string): Promise<string | null> {
  if (isTauriEnvironment()) {
    const result = await getTransport().invoke<string | null>("open_file_dialog", { title });
    return result ?? null;
  }
  const { pickServerPath } = await import("./serverPathPicker");
  return pickServerPath("file", title);
}

/// Open a URL in the OS default browser. In the desktop app `window.open` is a
/// no-op (the Tauri webview swallows it), so route through the opener command;
/// in a real browser `window.open` is correct.
export async function openExternal(url: string): Promise<void> {
  if (!url) return;
  if (isTauriEnvironment()) {
    await getTransport().invoke("open_url", { url });
    return;
  }
  window.open(url, "_blank", "noopener,noreferrer");
}

/// Open a native folder picker dialog and return the selected path.
export async function pickFolder(title?: string): Promise<string | null> {
  if (isTauriEnvironment()) {
    const result = await getTransport().invoke<string | null>("open_folder_dialog", { title });
    return result ?? null;
  }
  const { pickServerPath } = await import("./serverPathPicker");
  return pickServerPath("folder", title);
}
