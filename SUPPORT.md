# Getting help

oxfuzz has a single maintainer. There is no paid support and no guaranteed
response time, but questions and reports are read.

## Before you ask

- Read [Getting Started](docs/guides/GETTING_STARTED.md),
  [Install](docs/guides/INSTALL.md), and the
  [CLI reference](docs/guides/CLI_REFERENCE.md).
- Run `oxfuzz doctor`. It checks Docker, the sandbox image, and the bundled
  engines, and says how to fix a missing image.
- Look up your symptom in [Troubleshooting](docs/guides/TROUBLESHOOTING.md).
- Check the [support matrix](docs/guides/SUPPORT_MATRIX.md) to see whether
  your language, engine, and platform combination is supported.
- Search [existing issues](https://github.com/HenryCooper86/oxfuzz/issues),
  including closed ones.

## Where to ask

- **Feedback and open questions**: use
  [Discussions](https://github.com/HenryCooper86/oxfuzz/discussions). The
  release feedback thread is pinned there.
- **Usage questions**: open an issue with the
  [Question form](https://github.com/HenryCooper86/oxfuzz/issues/new?template=question.yml).
- **Bugs**: use the
  [Bug report form](https://github.com/HenryCooper86/oxfuzz/issues/new?template=bug_report.yml).
- **Ideas and feature requests**: use the
  [Feature request form](https://github.com/HenryCooper86/oxfuzz/issues/new?template=feature_request.yml).

## What to include

The more of this you include, the faster a question can be answered:

- the output of `oxfuzz --version`;
- your operating system, CPU architecture, and Docker runtime (Docker Desktop,
  OrbStack, Docker Engine on Linux, or Podman);
- whether you built from source or installed the desktop app;
- the output of `oxfuzz doctor`;
- the exact command you ran, or the steps you took in the desktop app;
- the engine and target language involved, if any;
- relevant log output. Re-run the command with `RUST_LOG=debug` for more
  detail.

Redact API keys, tokens, private target source, and crash inputs before
posting. Log output and configuration files can contain all of these. Name your
LLM provider type (for example `openai` or `ollama`) but never paste its key.

## Security issues

Do not report vulnerabilities in a public issue. Follow
[SECURITY.md](SECURITY.md) and use GitHub's private vulnerability reporting.

## Conduct

Everyone taking part is expected to follow the
[Code of Conduct](CODE_OF_CONDUCT.md).
