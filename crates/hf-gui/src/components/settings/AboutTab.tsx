// About tab -- version, links, credits, and a copyable system report.

import { useState } from "react";
import { Badge } from "../ui/Badge";
import { Button } from "../ui/Button";
import { Separator } from "../ui/Separator";
import { useToast } from "../ui/Toast";
import { getTransport, openExternal } from "../../lib";
import type { SystemStatus } from "../../types";
import { Crosshair, Github, BookOpen, ClipboardCheck } from "lucide-react";

const APP_VERSION = "0.1.0";
const REPO_URL = "https://github.com/hobot/hobot_fuzz";
const DOCS_URL = "https://github.com/hobot/hobot_fuzz/blob/main/docs/guides/GETTING_STARTED.md";

/** Build a Markdown environment report from the live system status, for pasting
 * into a bug report. Deliberately plain text (no emoji) per project convention. */
function buildReport(status: SystemStatus | null): string {
  const yn = (b: boolean | undefined) => (b ? "yes" : "no");
  const platform = typeof navigator === "undefined" ? "unknown" : navigator.userAgent;
  const lines = [
    "### hobot_fuzz environment report",
    "",
    `- App version: ${APP_VERSION}`,
    `- Platform: ${platform}`,
    status
      ? [
          `- Docker running: ${yn(status.docker)}`,
          `- Sandbox image built: ${yn(status.sandbox_image)}`,
          `- Engines: libFuzzer=${yn(status.libfuzzer)}, AFL++=${yn(status.aflplusplus)}, ` +
            `honggfuzz=${yn(status.honggfuzz)}, ClusterFuzzLite=${yn(status.clusterfuzzlite)}, ` +
            `syzkaller=${yn(status.syzkaller)}`,
          `- DefectDojo reachable: ${yn(status.defectdojo)}`,
        ].join("\n")
      : "- System status: unavailable (backend did not respond)",
  ];
  return lines.join("\n");
}

export function AboutTab() {
  const { toast } = useToast();
  const [copying, setCopying] = useState(false);

  async function copyReport() {
    setCopying(true);
    try {
      const status = await getTransport()
        .invoke<SystemStatus>("system_status_cmd")
        .catch(() => null);
      const report = buildReport(status);
      await navigator.clipboard?.writeText(report);
      toast({ title: "System report copied", description: "Paste it into your bug report.", variant: "success" });
    } catch (e) {
      toast({ title: "Could not copy system report", description: String(e), variant: "error" });
    } finally {
      setCopying(false);
    }
  }

  return (
    <div className="flex flex-col gap-4">
      <div className="flex items-center gap-4">
        <div
          className="flex items-center justify-center rounded-full"
          style={{ width: "56px", height: "56px", background: "var(--accent-subtle)", border: "1px solid var(--border)" }}
        >
          <Crosshair size={28} style={{ color: "var(--accent)" }} />
        </div>
        <div>
          <h2 className="text-lg font-semibold">hobot_fuzz</h2>
          <div className="flex items-center gap-2 mt-1">
            <Badge variant="accent">v{APP_VERSION}</Badge>
            <Badge>MIT License</Badge>
            <Badge variant="success">Rust + Tauri</Badge>
          </div>
        </div>
      </div>

      <Separator />

      <div className="flex flex-col gap-2">
        <h3 className="text-sm font-semibold">AI Fuzzing Agent</h3>
        <p className="text-xs text-text-secondary leading-relaxed">
          hobot_fuzz is an autonomous agent that discovers fuzzing targets, writes harnesses, drives
          open-source fuzzing engines (AFL++, honggfuzz, libFuzzer, ClusterFuzzLite), triages crashes,
          and iterates on corpus and coverage -- all under human-in-the-loop supervision.
        </p>
      </div>

      <Separator />

      <div className="flex flex-col gap-2">
        <h3 className="text-sm font-semibold">Engines</h3>
        <div className="flex flex-wrap gap-2">
          <Badge variant="accent">libFuzzer</Badge>
          <Badge variant="accent">AFL++</Badge>
          <Badge variant="accent">honggfuzz</Badge>
          <Badge variant="accent">ClusterFuzzLite</Badge>
        </div>
      </div>

      <div className="flex flex-col gap-2">
        <h3 className="text-sm font-semibold">Languages</h3>
        <div className="flex flex-wrap gap-2">
          <Badge>C</Badge>
          <Badge>C++</Badge>
          <Badge>Rust</Badge>
          <Badge>Go</Badge>
          <Badge>Python</Badge>
        </div>
      </div>

      <Separator />

      <div className="flex flex-col gap-2">
        <h3 className="text-sm font-semibold">Troubleshooting</h3>
        <p className="text-xs text-text-secondary">
          Copy a plain-text summary of your environment (app version, platform, Docker and engine
          availability) to include in a bug report.
        </p>
        <div>
          <Button variant="outline" size="sm" onClick={() => void copyReport()} loading={copying}>
            {!copying && <ClipboardCheck size={14} />}
            Copy system report
          </Button>
        </div>
      </div>

      <Separator />

      <div className="flex flex-col gap-2">
        <h3 className="text-sm font-semibold">Links</h3>
        <div className="flex flex-col gap-1 items-start">
          <button
            onClick={() => void openExternal(REPO_URL)}
            className="text-xs text-accent flex items-center gap-2 hover:underline"
            style={{ background: "none", border: "none", padding: 0, cursor: "pointer" }}
          >
            <Github size={14} /> GitHub Repository
          </button>
          <button
            onClick={() => void openExternal(DOCS_URL)}
            className="text-xs text-accent flex items-center gap-2 hover:underline"
            style={{ background: "none", border: "none", padding: 0, cursor: "pointer" }}
          >
            <BookOpen size={14} /> Documentation
          </button>
          <span className="text-xs text-text-muted mt-1">
            An in-app guide is available under <strong className="text-text-primary">Help &amp; Docs</strong> in the sidebar.
          </span>
        </div>
      </div>
    </div>
  );
}
