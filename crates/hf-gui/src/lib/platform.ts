// Platform abstraction for file dialogs.

import { getTransport } from "./index";
import { isTauriEnvironment } from "./transport";

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