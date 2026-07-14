// About tab -- version, links, credits, and a copyable system report.

import { useState } from "react";
import { Badge } from "../ui/Badge";
import { Button } from "../ui/Button";
import { Separator } from "../ui/Separator";
import { useToast } from "../ui/Toast";
import { useI18n } from "../../i18n";
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
  const { t } = useI18n();
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
      toast({ title: t("settings.about.reportCopied"), description: t("settings.about.reportCopiedDesc"), variant: "success" });
    } catch (e) {
      toast({ title: t("settings.about.reportCopyFailed"), description: String(e), variant: "error" });
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
        <h3 className="text-sm font-semibold">{t("settings.about.aiFuzzingAgent")}</h3>
        <p className="text-xs text-text-secondary leading-relaxed">
          {t("settings.about.description")}
        </p>
      </div>

      <Separator />

      <div className="flex flex-col gap-2">
        <h3 className="text-sm font-semibold">{t("settings.about.engines")}</h3>
        <div className="flex flex-wrap gap-2">
          <Badge variant="accent">libFuzzer</Badge>
          <Badge variant="accent">AFL++</Badge>
          <Badge variant="accent">honggfuzz</Badge>
          <Badge variant="accent">ClusterFuzzLite</Badge>
        </div>
      </div>

      <div className="flex flex-col gap-2">
        <h3 className="text-sm font-semibold">{t("settings.about.languages")}</h3>
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
        <h3 className="text-sm font-semibold">{t("settings.about.troubleshooting")}</h3>
        <p className="text-xs text-text-secondary">
          {t("settings.about.troubleshootingDesc")}
        </p>
        <div>
          <Button variant="outline" size="sm" onClick={() => void copyReport()} loading={copying}>
            {!copying && <ClipboardCheck size={14} />}
            {t("settings.about.copyReport")}
          </Button>
        </div>
      </div>

      <Separator />

      <div className="flex flex-col gap-2">
        <h3 className="text-sm font-semibold">{t("settings.about.links")}</h3>
        <div className="flex flex-col gap-1 items-start">
          <button
            onClick={() => void openExternal(REPO_URL)}
            className="text-xs text-accent flex items-center gap-2 hover:underline"
            style={{ background: "none", border: "none", padding: 0, cursor: "pointer" }}
          >
            <Github size={14} /> {t("settings.about.repo")}
          </button>
          <button
            onClick={() => void openExternal(DOCS_URL)}
            className="text-xs text-accent flex items-center gap-2 hover:underline"
            style={{ background: "none", border: "none", padding: 0, cursor: "pointer" }}
          >
            <BookOpen size={14} /> {t("settings.about.docs")}
          </button>
          <span className="text-xs text-text-muted mt-1">
            {t("settings.about.guidePre")}<strong className="text-text-primary">{t("nav.help")}</strong>{t("settings.about.guidePost")}
          </span>
        </div>
      </div>
    </div>
  );
}
