import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import "virtual:uno.css";
import "./styles/index.css";
import App from "./App";

// Set host/platform datasets for CSS platform-specific rules.
function resolveHostDataset() {
  const html = document.documentElement;
  if (typeof window !== "undefined" && "__TAURI_INTERNALS__" in window) {
    html.dataset.host = "tauri";
  } else {
    html.dataset.host = "web";
  }
  const platform = navigator.platform.toLowerCase();
  if (platform.includes("mac")) html.dataset.platform = "macos";
  else if (platform.includes("linux")) html.dataset.platform = "linux";
  else html.dataset.platform = "windows";
}

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <App />
  </StrictMode>,
);

resolveHostDataset();