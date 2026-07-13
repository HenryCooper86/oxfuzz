# Issue-Tracker Integration -- Design

## Goal

File triaged crashes as **GitHub** or **GitLab** issues in the **fuzzed
project's** repository, so fuzzing results land in the team's own tracker with no
manual re-entry.

## The bug this replaces

`workbench::gitlab_issue_export` guessed the repo by running `git -C <project>
remote get-url origin`. When the fuzzed project is not its own git repo (e.g.
`tests/fixtures/vuln_c` inside the hobot_fuzz checkout), `git -C` walks up to the
enclosing repo and returns **hobot_fuzz's** remote -- so crash issues were filed
against hobot_fuzz. There was also no GitHub support and no way to set the repo
or credentials. This integration makes all of that explicit config.

## Auth: token, not password

Auth is a **Personal Access Token**, mirroring the provider/DefectDojo secret
pattern (`api_token` direct, or `api_token_env` naming an environment variable;
never logged). There is deliberately **no password field**: GitHub removed
password auth for its API in 2021 and GitLab's API is token-based. A `username`
is kept for attribution/display only, never for authentication.

## Two flows

- **File via API** (when a token is set): POST to the provider's REST API, which
  creates the issue and returns its URL; the app opens it. Primary flow.
- **Open prefilled new-issue page** (no token / fallback): open the target repo's
  provider-correct new-issue URL in the browser. Filing is always a user-initiated
  button press (an outward action).

## Config -- `config/issue_tracker.toml` (+ `.example`)

| key | meaning |
|-----|---------|
| `provider` | `github` \| `gitlab` \| `none` |
| `host` | blank = github.com / gitlab.com; set for Enterprise / self-hosted |
| `repo` | GitHub `owner/repo`; GitLab `group/project` or numeric project id |
| `api_token` / `api_token_env` | PAT direct (desktop) or via env var (CLI/CI) |
| `username` | attribution/display only |
| `labels` | applied to every filed issue (default hobot-fuzz/fuzzing/crash) |
| `verify_tls` | verify the server certificate |

Registered in `config.rs` `CONFIG_SECTIONS` + `bundled_example`. The live
`issue_tracker.toml` is gitignored (it may hold a token).

## Layering (AGENTS.md 2.9 -- all logic in hf-service)

| Layer | Location |
|-------|----------|
| Logic | `hf-service/src/issue_tracker.rs`: `Provider`, `IssueTrackerConfig`, `resolve_config`/`load_config`/`is_configured`/`resolve_token`, pure URL/endpoint/body builders, `IssueTrackerClient` (`create_issue` + `test_connection`) |
| Draft | `workbench.rs`: `IssueExport` (provider-aware, config-driven target with git-remote fallback), `issue_export`, `file_issue` |
| Orchestration | `container.rs`: `issue_export`, `file_issue`, `issue_tracker_configured`, `issue_tracker_test_connection` |
| Web | `hf-web`: `POST /issues/export`, `POST /issues/file`, `GET /issues/configured`, `GET /issues/test` (legacy `POST /gitlab/issue` kept) |
| Tauri | `commands.rs`: `issue_export`, `file_issue`, `issue_tracker_configured`, `issue_tracker_test_connection` |
| GUI | Settings > **Issue Tracker** section (config form + Test connection + Open repo); Dashboard issue draft: provider-labelled, "File issue" (API) + "Open in browser" |

## Provider specifics

| | GitHub | GitLab |
|--|--------|--------|
| New-issue URL | `{repo}/issues/new?title=&body=&labels=a,b,c` | `{repo}/-/issues/new?issue[title]=&issue[description]=&issue[label_names][]=` |
| API create | `POST {api}/repos/{repo}/issues` (`api.github.com`, or `{host}/api/v3` Enterprise), `Authorization: Bearer` | `POST {host}/api/v4/projects/{urlencoded repo|id}/issues`, `PRIVATE-TOKEN` |
| Create body | `{title, body, labels:[...]}` | `{title, description, labels:"a,b,c"}` |
| Created URL / number | `html_url` / `number` | `web_url` / `iid` |

## Non-goals

- No password auth, ever.
- No auto-filing: issues are only ever filed on an explicit button press.
- The config is authoritative for the target; git-remote derivation remains only
  as a best-effort fallback when the tracker is unconfigured.
