# Desktop app screenshots

These images are the product evidence rendered by the top-level `README.md`.
Keep the filenames, content, and descriptions synchronized with the current
desktop app. The current set was refreshed from the native macOS application on
2026-07-16 at 1326 x 768 pixels.

## Capture requirements

1. Build and launch the native app:

   ```bash
   ./scripts/build-app.sh
   open target/release/bundle/macos/hobot_fuzz.app
   ```

2. Use a deterministic fixture or a neutral demonstration project. A retained
   campaign for `tests/fixtures/examples/libfuzzer_fuzzme` is suitable for
   populated discovery, harness, run, triage, and artifact views.
3. Capture the full app viewport at a consistent size between 1200 and 1440
   pixels wide. Save true PNG files; do not place JPEG data behind a `.png`
   extension.
4. Never start a fuzzing campaign only to create a screenshot. Use retained
   evidence from a previously approved sandboxed campaign, or perform a
   separately authorized bounded campaign through the normal product workflow.
5. Before committing, check every image for API keys, access tokens, private
   repository URLs, personal messages, customer data, and unrelated local
   paths. Provider secrets must never be visible, even when a field is masked.

During frontend development, the web surface can also be inspected with
`cd crates/hf-gui && npm run dev:web`, but README screenshots should come from
the native application unless the documented feature is web-only.

## Required set

| File | View | What it must communicate |
| --- | --- | --- |
| `hero.png` | Dashboard | Operational readiness, evidence counts, harness review, recent runs, and crash handoff. This is the README hero image. |
| `discover.png` | Discover | A populated, ranked Target Inventory with fit score and source location. |
| `harness.png` | Harness | The active revision plus sandbox qualification, human promotion, and seed-corpus flow. |
| `run.png` | Run | The selected approved target, enabled engine, bounded duration, and retained campaign metrics. |
| `triage.png` | Triage | A deduplicated finding with sanitizer kind and exploitability classification. |
| `artifacts.png` | Artifacts | Persisted crash reproducers and corpus entries with operator actions. |
| `settings.png` | Settings > Fuzzing | Engine availability, bounded resource defaults, and mandatory protections that cannot be weakened. |
| `automotive.png` | Automotive | Evidence-backed report composition, AI advisory boundaries, virtual versus physical replay policy, and retained operation history. |

Optional additions should tell a materially different product story, not repeat
an existing view. Candidates include Reports, Run History, Policy Audit,
DefectDojo, and the first-run setup wizard.

## Verification

From the repository root:

```bash
file docs/screenshots/*.png
git diff --check
```

Every required file should report `PNG image data`, use the same viewport size,
and match the README alt text and surrounding claims. If the UI workflow or
sidebar changes, update the screenshots, this inventory, the README, and the
Getting Started guide in the same change.
