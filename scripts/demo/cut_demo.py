#!/usr/bin/env python3
"""Cut a raw screen recording into a website demo clip.

Reads an edit spec (JSON), keeps the listed segments in order, speeds up the
ones with "speed" > 1 and marks them with a visible "N x" badge, and writes:

  <out>.mp4      H.264, yuv420p, 30 fps, faststart
  <out>.en.vtt   captions, one cue per segment that has one
  <out>.zh.vtt
  <out>.jpg      poster frame

Spec:
  {"input": "raw.mkv", "width": 1440, "poster_at": 12.0, "crop": "w:h:x:y",
   "segments": [{"start": 33, "end": 58, "speed": 1,
                 "en": "caption", "zh": "字幕"}]}

A sped-up segment's caption should say so; the badge shows it either way.
Needs ffmpeg and ImageMagick (`magick`) on PATH; FONT names the badge font.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tempfile
from pathlib import Path


FONT = "/System/Library/Fonts/Supplemental/Arial Bold.ttf"


def badge(path: Path, speed: float) -> None:
    label = f"{speed:g}x faster"
    subprocess.run(
        ["magick", "-size", "260x64", "xc:none", "-fill", "rgba(0,0,0,0.72)",
         "-draw", "roundrectangle 0,0 259,63 14,14", "-fill", "#f2d675",
         "-font", FONT, "-pointsize", "30", "-gravity", "center",
         "-annotate", "+0+0", label, str(path)],
        check=True,
    )


def timestamp(seconds: float) -> str:
    millis = round(seconds * 1000)
    hours, millis = divmod(millis, 3_600_000)
    minutes, millis = divmod(millis, 60_000)
    secs, millis = divmod(millis, 1000)
    return f"{hours:02d}:{minutes:02d}:{secs:02d}.{millis:03d}"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("spec")
    parser.add_argument("out", help="output path without extension")
    parser.add_argument("--crf", type=int, default=27)
    args = parser.parse_args()

    spec_path = Path(args.spec)
    spec = json.loads(spec_path.read_text())
    source = (spec_path.parent / spec["input"]).resolve()
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    width = spec.get("width", 1440)

    inputs = ["-i", str(source)]
    chains, labels, cues = [], [], []
    clock = 0.0
    with tempfile.TemporaryDirectory() as scratch:
        for index, segment in enumerate(spec["segments"]):
            start, end = float(segment["start"]), float(segment["end"])
            speed = float(segment.get("speed", 1))
            crop = f"crop={spec['crop']}," if spec.get("crop") else ""
            chain = (f"[0:v]trim=start={start}:end={end},setpts=(PTS-STARTPTS)/{speed},"
                     f"{crop}fps=30,scale={width}:-2:flags=lanczos")
            if speed > 1:
                image = Path(scratch) / f"badge{index}.png"
                badge(image, speed)
                inputs += ["-loop", "1", "-i", str(image)]
                badge_input = inputs.count("-i") - 1
                chain += f"[base{index}];[base{index}][{badge_input}:v]overlay=W-w-28:28:shortest=1"
            chain += f"[v{index}]"
            chains.append(chain)
            labels.append(f"[v{index}]")
            length = (end - start) / speed
            if segment.get("en"):
                cues.append((clock, clock + length, segment["en"], segment.get("zh", segment["en"])))
            clock += length

        graph = ";".join(chains) + ";" + "".join(labels) + f"concat=n={len(labels)}:v=1:a=0[out]"
        subprocess.run(
            ["ffmpeg", "-v", "error", "-y", *inputs, "-filter_complex", graph, "-map", "[out]",
             "-c:v", "libx264", "-preset", "slow", "-crf", str(args.crf), "-pix_fmt", "yuv420p",
             "-movflags", "+faststart", "-an", str(out.with_suffix(".mp4"))],
            check=True,
        )

    for language, column in (("en", 2), ("zh", 3)):
        lines = ["WEBVTT", ""]
        for number, cue in enumerate(cues, 1):
            lines += [str(number), f"{timestamp(cue[0])} --> {timestamp(cue[1])}", cue[column], ""]
        out.with_suffix(f".{language}.vtt").write_text("\n".join(lines))

    poster_at = float(spec.get("poster_at", min(clock / 2, 10)))
    subprocess.run(
        ["ffmpeg", "-v", "error", "-y", "-ss", str(poster_at), "-i", str(out.with_suffix(".mp4")),
         "-frames:v", "1", "-q:v", "4", str(out.with_suffix(".jpg"))],
        check=True,
    )
    print(f"{out.with_suffix('.mp4')}: {clock:.1f} s, {len(cues)} captions")
    return 0


if __name__ == "__main__":
    sys.exit(main())
