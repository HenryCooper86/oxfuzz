// Platform abstraction for file dialogs.

import { getTransport } from "./index";
import { isTauriEnvironment } from "./transport";

/// Open a native file picker dialog and return the selected file path.
export async function pickFile(title?: string): Promise<string | null> {
  if (isTauriEnvironment()) {
    const result = await getTransport().invoke<string | null>("open_file_dialog", { title });
    return result ?? null;
  }
  // Web fallback: a plain file input yields only the basename, not a full path.
  return new Promise((resolve) => {
    const input = document.createElement("input");
    input.type = "file";
    input.onchange = () => {
      const file = input.files?.[0];
      resolve(file ? file.name : null);
    };
    input.click();
  });
}

/// Open a native folder picker dialog and return the selected path.
export async function pickFolder(): Promise<string | null> {
  if (isTauriEnvironment()) {
    const result = await getTransport().invoke<string | null>("open_folder_dialog");
    return result ?? null;
  }
  // Web fallback
  return new Promise((resolve) => {
    const input = document.createElement("input");
    input.type = "file";
    const fileInput = input as HTMLInputElement & { webkitdirectory: boolean };
    fileInput.webkitdirectory = true;
    input.onchange = () => {
      if (input.files && input.files.length > 0) {
        const file = input.files[0] as File & { webkitRelativePath?: string };
        const rel = file.webkitRelativePath;
        resolve(rel?.split("/").slice(0, -1).join("/") ?? "");
      } else {
        resolve(null);
      }
    };
    input.click();
  });
}