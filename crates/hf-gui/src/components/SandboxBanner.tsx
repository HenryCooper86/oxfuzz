import { useEffect, useState } from "react";
import { AlertTriangle } from "lucide-react";
import { getTransport } from "../lib";
import type { SystemStatus } from "../types";

// A persistent, actionable banner shown in the Docker-dependent views (Harness,
// Run) when the sandbox can't execute -- so a first-run user learns *why* a
// build/run is blocked and what to do, instead of hitting a silent gate. Every
// harness build and fuzz run goes through the sandbox (AGENTS.md 2.12), so with
// Docker down or the image missing nothing can proceed.
export function SandboxBanner() {
  const [status, setStatus] = useState<SystemStatus | null>(null);

  useEffect(() => {
    let cancelled = false;
    const poll = () => {
      getTransport()
        .invoke<SystemStatus>("system_status_cmd")
        .then((s) => !cancelled && setStatus(s))
        .catch(() => {});
    };
    poll();
    // Docker/image state changes out-of-band (user starts Docker, image builds),
    // so re-check periodically; clears itself once the sandbox is ready.
    const id = setInterval(poll, 8000);
    return () => {
      cancelled = true;
      clearInterval(id);
    };
  }, []);

  if (!status || (status.docker && status.sandbox_image)) return null;

  const dockerDown = !status.docker;
  const title = dockerDown ? "Docker isn't running" : "Fuzzing sandbox image not built";
  const detail = dockerDown
    ? "Every harness build and fuzz run executes inside the Docker sandbox. Start Docker Desktop (or your Docker daemon), then retry."
    : "The sandbox image is missing. Build it with ./rebuild-sandbox-image.command (the desktop build script builds it too), then retry.";

  return (
    <div
      className="surface-card flex items-start gap-3"
      style={{ padding: "var(--space-md)", borderLeft: "3px solid var(--warning, #d9a441)" }}
      role="status"
    >
      <AlertTriangle size={18} style={{ color: "var(--warning, #d9a441)", flexShrink: 0, marginTop: 1 }} />
      <div className="min-w-0">
        <p className="text-sm font-medium text-text-primary">{title}</p>
        <p className="text-xs text-text-secondary mt-1" style={{ lineHeight: 1.5 }}>
          {detail}
        </p>
      </div>
    </div>
  );
}
