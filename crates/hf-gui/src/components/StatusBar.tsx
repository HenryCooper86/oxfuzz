import { useState, useEffect } from "react";
import { getTransport } from "../lib";
import type { SystemStatus } from "../types";
import { Container, Terminal } from "lucide-react";

export function StatusBar() {
  const [status, setStatus] = useState<SystemStatus | null>(null);
  const [time, setTime] = useState(new Date().toLocaleTimeString());

  useEffect(() => {
    const interval = setInterval(() => setTime(new Date().toLocaleTimeString()), 1000);
    return () => clearInterval(interval);
  }, []);

  useEffect(() => {
    getTransport()
      .invoke<SystemStatus>("system_status")
      .then(setStatus)
      .catch(() => setStatus({ docker: false, clang: false, afl: false, honggfuzz: false }));
  }, []);

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
            <StatusDot label="Clang" active={status.clang} icon={<Terminal size={11} />} />
            <StatusDot label="AFL++" active={status.afl} />
            <StatusDot label="honggfuzz" active={status.honggfuzz} />
          </>
        )}
      </div>
      <div className="flex items-center gap-3">
        <span>{time}</span>
      </div>
    </footer>
  );
}

function StatusDot({ label, active, icon }: { label: string; active: boolean; icon?: React.ReactNode }) {
  return (
    <div className="flex items-center gap-1">
      {icon}
      <span style={{ color: active ? "var(--success)" : "var(--text-muted)" }}>{label}</span>
      <span
        style={{
          width: "6px",
          height: "6px",
          borderRadius: "50%",
          background: active ? "var(--success)" : "var(--text-muted)",
          opacity: active ? 1 : 0.4,
        }}
      />
    </div>
  );
}