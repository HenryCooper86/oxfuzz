---
name: Bug report
about: Something oxfuzz does that it should not, or fails to do
title: ""
labels: bug
assignees: ""
---

<!--
Security-sensitive findings do NOT go here. Report them privately through
SECURITY.md so they are not disclosed in a public issue.
-->

## What happened

A clear description of the incorrect behavior.

## What you expected

What should have happened instead.

## Reproduction

Steps to reproduce, ideally the exact commands:

```text
oxfuzz ...
```

- Subcommand / surface (CLI, desktop app, REST): 
- Engine (afl++, honggfuzz, libfuzzer, ...), if relevant: 
- Target language (C, C++, Rust, ...), if relevant: 

## Environment

- oxfuzz version or commit: 
- OS and version: 
- Runtime (Docker sandbox / native), and Docker version if used: 
- LLM provider(s) configured: 

## Logs and evidence

Relevant output. Redact API keys, target source, and crash artifacts.

```text

```

## Additional context

Anything else that helps, such as whether it worked in a previous version.
