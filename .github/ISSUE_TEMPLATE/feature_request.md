---
name: Feature request
about: Propose a capability or improvement
title: ""
labels: enhancement
assignees: ""
---

## Problem

The concrete problem or limitation this would address. What are you trying to do
that oxfuzz does not currently let you do well?

## Proposed solution

What you would like to happen. If it touches a specific subsystem
(discovery, harness, engine, crash, corpus, coverage, agent, guardrails), say
which.

## Alternatives considered

Other approaches you weighed and why they fall short.

## Scope and safety

- [ ] This does not weaken sandboxing, guardrails, or human-in-the-loop approval.
- [ ] This fits the inward-pointing layering (business logic in `hf-service`;
      presentation layers stay thin), as described in `CLAUDE.md` / `AGENTS.md`.

## Additional context

Links to designs, prior art in other fuzzers, or references.
