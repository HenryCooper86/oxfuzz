// ---------------------------------------------------------------------------
// GeneralTab -- Paths, Appearance, Behavior, Setup (modeled on y-agent).
// ---------------------------------------------------------------------------

import { useEffect, useState } from "react";
import { Copy, Wand2 } from "lucide-react";
import { getTransport } from "../../lib";
import { usePrefs } from "../../providers/PrefsContext";
import { useToast } from "../ui/Toast";
import { Button, Input, Select, Switch } from "../ui";
import { SettingsGroup, SettingsItem } from "../ui/SettingsGroup";

export function GeneralTab({ onRunWizard }: { onRunWizard?: () => void }) {
  const {
    theme,
    setTheme,
    fontSize,
    setFontSize,
    sendOnEnter,
    setSendOnEnter,
    customDecorations,
    setCustomDecorations,
    sandboxArch,
    setSandboxArch,
  } = usePrefs();
  const { toast } = useToast();
  const [configPath, setConfigPath] = useState("");
  const [dataPath, setDataPath] = useState("");

  useEffect(() => {
    getTransport()
      .invoke<{ config_dir: string; data_dir: string }>("app_paths")
      .then((p) => {
        setConfigPath(p.config_dir);
        setDataPath(p.data_dir);
      })
      .catch(() => {
        /* ignore */
      });
  }, []);

  async function copy(value: string) {
    try {
      await navigator.clipboard.writeText(value);
      toast({ title: "Copied to clipboard", variant: "success" });
    } catch {
      /* ignore */
    }
  }

  return (
    <div className="flex flex-col" style={{ animation: "fadeIn 0.2s ease" }}>
      <SettingsGroup title="Paths">
        <SettingsItem title="Config Directory" stacked>
          <PathField value={configPath} onCopy={() => copy(configPath)} />
        </SettingsItem>
        <SettingsItem title="Data Directory" stacked>
          <PathField value={dataPath} onCopy={() => copy(dataPath)} />
        </SettingsItem>
      </SettingsGroup>

      <SettingsGroup title="Appearance">
        <SettingsItem title="Theme">
          <Select
            value={theme}
            onChange={(v) => setTheme(v === "light" ? "light" : "dark")}
            options={[
              { value: "dark", label: "Dark" },
              { value: "light", label: "Light" },
            ]}
            className="w-[140px]"
          />
        </SettingsItem>
        <SettingsItem title="Font Size">
          <div className="flex items-center gap-3">
            <input
              type="range"
              min={12}
              max={20}
              value={fontSize}
              onChange={(e) => setFontSize(Number(e.target.value))}
              style={{ accentColor: "var(--accent)", width: "160px" }}
            />
            <span className="text-xs text-text-secondary" style={{ width: "34px", textAlign: "right" }}>
              {fontSize}px
            </span>
          </div>
        </SettingsItem>
        <SettingsItem
          title="Custom window decorations"
          description="Hide the native titlebar and render an Apple-style layered chrome. Recommended on macOS."
        >
          <Switch checked={customDecorations} onChange={setCustomDecorations} />
        </SettingsItem>
      </SettingsGroup>

      <SettingsGroup title="Behavior">
        <SettingsItem
          title="Send message on Enter"
          description="When enabled, press Enter to send and Shift+Enter for a newline. When off, use Cmd/Ctrl+Enter to send."
        >
          <Switch checked={sendOnEnter} onChange={setSendOnEnter} />
        </SettingsItem>
      </SettingsGroup>

      <SettingsGroup
        title="Sandbox"
        description="The Docker sandbox is built and run for this architecture. Choose the one matching your fuzzing target's ABI; a non-host arch runs under emulation (qemu)."
      >
        <SettingsItem
          title="Architecture"
          description="linux/arm64 (Apple Silicon native) or linux/amd64 (x86_64). Changing this rebuilds the sandbox image."
        >
          <Select
            value={sandboxArch}
            onChange={(v) => setSandboxArch(v === "linux/amd64" ? "linux/amd64" : "linux/arm64")}
            options={[
              { value: "linux/arm64", label: "linux/arm64" },
              { value: "linux/amd64", label: "linux/amd64 (x86)" },
            ]}
            className="w-[190px]"
          />
        </SettingsItem>
      </SettingsGroup>

      <SettingsGroup
        title="Setup"
        description="Re-run the initial setup wizard to reconfigure providers, runtime, engines, and guardrails."
      >
        <SettingsItem title="Setup Wizard">
          <Button variant="outline" onClick={onRunWizard}>
            <Wand2 size={14} />
            Run Setup Wizard
          </Button>
        </SettingsItem>
      </SettingsGroup>
    </div>
  );
}

function PathField({ value, onCopy }: { value: string; onCopy: () => void }) {
  return (
    <div className="relative flex items-center w-full">
      <Input mono readOnly value={value} title={value} className="pr-9 text-text-secondary select-all" />
      <Button variant="icon" size="sm" className="absolute right-1" onClick={onCopy} title="Copy path">
        <Copy size={13} />
      </Button>
    </div>
  );
}
