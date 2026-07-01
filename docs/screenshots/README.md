# Desktop app screenshots

These images are referenced by the top-level `README.md`. Drop the PNG files
here with the exact filenames below and they will render in the README.

## How to capture

1. Build and launch the desktop app:
   ```bash
   ./scripts/build-app.sh
   open target/release/bundle/macos/hobot_fuzz.app
   ```
   (During development you can also use `cd crates/hf-gui && npm run dev`.)
2. On macOS, capture a single window with **Cmd-Shift-4**, then press **Space**
   and click the app window (this yields a clean shot with the native rounded
   corners and drop shadow). Save each file into this directory.
3. A window width around **1200-1440 px** matches the README layout best.

## The set the README expects

| File | View (sidebar) | What it should show |
| --- | --- | --- |
| `hero.png` | AI Assistant | The chat agent mid-conversation (the app's signature view). Used as the hero image at the top of the README. |
| `discover.png` | Discover | A ranked Target Inventory after scanning a project (fit scores, input surface, reachability). Load `tests/fixtures/sample_c` for a quick populated example. |
| `run.png` | Run | A live fuzz run: exec/s, coverage edges, elapsed, and the streaming log. |
| `triage.png` | Triage | Triaged crashes with CASR severity badges and a drafted bug report. |
| `artifacts.png` | Artifacts | The Crashes + Corpus browse view (persisted artifacts across targets). |
| `settings.png` | Settings | The provider-pool configuration panel. |

Optional extras the README will pick up if present (nice-to-have, not required):
`setup.png` (first-run wizard), `harness.png`, `corpus.png`, `coverage.png`.
