import { useState, useEffect } from "react";
import { getTransport } from "../lib";
import { usePrefs } from "../providers/PrefsContext";
import { useRunStatus } from "../providers/RunStatusContext";
import type { SystemStatus } from "../types";
import { Container, Box } from "lucide-react";

const EMPTY_STATUS: SystemStatus = {
  docker: false,
  sandbox_image: false,
  libfuzzer: false,
  aflplusplus: false,
  honggfuzz: false,
  clusterfuzzlite: false,
  syzkaller: false,
};

// Engine display order + how each maps to a SystemStatus flag and the engine id
// the Run view reports while running (so we can highlight the active one).
const ENGINES: { label: string; key: keyof SystemStatus; runId: string }[] = [
  { label: "libFuzzer", key: "libfuzzer", runId: "libfuzzer" },
  { label: "AFL++", key: "aflplusplus", runId: "afl++" },
  { label: "honggfuzz", key: "honggfuzz", runId: "honggfuzz" },
  { label: "ClusterFuzzLite", key: "clusterfuzzlite", runId: "clusterfuzzlite" },
  { label: "syzkaller", key: "syzkaller", runId: "syzkaller" },
];

export function StatusBar() {
  const { sandboxArch } = usePrefs();
  const { activeEngine } = useRunStatus();
  const [status, setStatus] = useState<SystemStatus | null>(null);
  const [dockerMsg, setDockerMsg] = useState<string | null>(null);
  const [time, setTime] = useState(new Date().toLocaleTimeString());

  useEffect(() => {
    const interval = setInterval(() => setTime(new Date().toLocaleTimeString()), 1000);
    return () => clearInterval(interval);
  }, []);

  useEffect(() => {
    const t = getTransport();
    let unlisten: (() => void) | undefined;

    // Live progress while Docker is brought up / the image is built.
    t.listen<{ message: string }>("docker:status", (e) => setDockerMsg(e.payload.message))
      .then((u) => { unlisten = u; })
      .catch(() => {});

    // Kick off the Docker bootstrap (start daemon + ensure the image is built
    // for the selected arch). Re-runs when the sandbox arch changes, rebuilding
    // the image for the new platform. Falls back to a plain status read.
    t.invoke<SystemStatus>("ensure_docker", { arch: sandboxArch })
      .then(setStatus)
      .catch(() =>
        t.invoke<SystemStatus>("system_status").then(setStatus).catch(() => setStatus(EMPTY_STATUS)),
      );

    // Keep the indicators fresh (the daemon can stop/start under us).
    const poll = setInterval(() => {
      t.invoke<SystemStatus>("system_status").then(setStatus).catch(() => {});
    }, 5000);

    return () => {
      if (unlisten) unlisten();
      clearInterval(poll);
    };
  }, [sandboxArch]);

  return (
    <footer
      className="flex items-center justify-between flex-shrink-0 select-none"
      style={{
        height: "28px",
        padding: "0 var(--space-lg)",
        background: "var(--surface-secondary)",
        borderTop: "1px solid var(--border)",
        fontSize: "11px",
        color: "var(--text-muted)",
      }}
    >
      <div className="flex items-center gap-3">
        {status && (
          <>
            <StatusDot label="Docker" active={status.docker} icon={<Container size={11} />} />
            <StatusDot label="Sandbox" active={status.sandbox_image} icon={<Box size={11} />} />
            <span style={{ width: "1px", height: "12px", background: "var(--border)" }} />
            {ENGINES.map((e) => (
              <StatusDot
                key={e.runId}
                label={e.label}
                active={Boolean(status[e.key])}
                running={activeEngine === e.runId}
              />
            ))}
          </>
        )}
        {dockerMsg && !(status?.docker && status?.sandbox_image) && (
          <span style={{ color: "var(--text-secondary)" }}>{dockerMsg}</span>
        )}
      </div>
      <div className="flex items-center gap-3">
        {activeEngine && (
          <span className="flex items-center gap-1.5" style={{ color: "var(--accent)" }}>
            <span
              style={{
                width: "6px",
                height: "6px",
                borderRadius: "50%",
                background: "var(--accent)",
                animation: "pulse 1.2s ease-in-out infinite",
              }}
            />
            Fuzzing: {ENGINES.find((e) => e.runId === activeEngine)?.label ?? activeEngine}
          </span>
        )}
        <span>{time}</span>
      </div>
    </footer>
  );
}

function StatusDot({
  label,
  active,
  icon,
  running,
}: {
  label: string;
  active: boolean;
  icon?: React.ReactNode;
  running?: boolean;
}) {
  const color = running ? "var(--accent)" : active ? "var(--success)" : "var(--text-muted)";
  return (
    <div className="flex items-center gap-1" title={running ? `${label} (running)` : label}>
      {icon}
      <span style={{ color }}>{label}</span>
      <span
        style={{
          width: "6px",
          height: "6px",
          borderRadius: "50%",
          background: color,
          opacity: active || running ? 1 : 0.4,
          animation: running ? "pulse 1.2s ease-in-out infinite" : undefined,
        }}
      />
    </div>
  );
}
