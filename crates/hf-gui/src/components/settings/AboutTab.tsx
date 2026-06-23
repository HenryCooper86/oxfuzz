// About tab -- version, links, credits.

import { Badge } from "../ui/Badge";
import { Separator } from "../ui/Separator";
import { Crosshair, Github, BookOpen } from "lucide-react";

export function AboutTab() {
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
            <Badge variant="accent">v0.1.0</Badge>
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
        <h3 className="text-sm font-semibold">Links</h3>
        <div className="flex flex-col gap-1">
          <a href="#" className="text-xs text-accent flex items-center gap-2 hover:underline"><Github size={14} /> GitHub Repository</a>
          <a href="#" className="text-xs text-accent flex items-center gap-2 hover:underline"><BookOpen size={14} /> Documentation</a>
        </div>
      </div>
    </div>
  );
}