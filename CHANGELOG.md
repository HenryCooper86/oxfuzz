# Changelog

Notable user-facing changes, newest first. Entries are written when a change
lands rather than at release time: section 1 of `docs/guides/RELEASE_CHECKLIST.md`
asks the releaser to review user-facing changes, migrations, and configuration
compatibility, and this is what that review reads from.

Versions match the release commits that bump `Cargo.toml`.

## Unreleased

### Changed

- **The campaign scheduler starts disarmed, and missed occurrences are held
  until it is armed.** A schedule with a `catch_up` or `backfill` missed policy
  used to replay everything it missed as soon as the process came back up.
  Recovery still restores that work, but it now waits for an explicit decision:
  `POST /schedule/arm`, or `oxfuzz arm` for a headless server (`--status` to
  check, `--off` to withdraw). A restart on its own is no longer treated as
  consent to resume a campaign that may be hours stale and pointed at a project
  which has changed in the meantime.

  **If you rely on catch-up firing automatically after a restart, you must now
  arm the server.** Nothing fires until you do, and held work is discarded on
  shutdown.

- **Oversized tool results are written to disk and replaced with a preview plus
  a locator**, instead of being truncated to a head and tail with the middle
  discarded. Artifacts live under the app's private state directory beside the
  run journal, not in your project. The store bounds itself at roughly 256 MiB,
  evicting the oldest artifacts as new ones arrive.

### Security

- **Processes oxfuzz spawns on the host no longer inherit its environment.**
  The `docker` CLI, `git`, `pandoc`, the DefectDojo lifecycle commands, and the
  daemon-start helpers now start from a scrubbed copy: variables whose names
  contain `KEY`, `SECRET`, `TOKEN`, or `PASSWORD`, plus everything prefixed
  `HF_`, are dropped. `PATH`, `HOME`, locale, and proxy settings survive. If a
  helper on your system needed one of the dropped variables, it will no longer
  see it.
