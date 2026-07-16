# Security policy

hobot_fuzz builds and runs untrusted fuzzing workloads, so security reports are
especially important. Please report suspected vulnerabilities privately.

## Supported versions

Security fixes target the current default branch and the latest tagged release.
Older development snapshots may not receive backports. If you are unsure
whether a version is supported, include its exact commit SHA in the report.

## Private reporting

Create a confidential issue in this GitLab project, or contact the repository
maintainers through an established private channel. Do not post exploit details,
credentials, private target code, or working reproducers in a public issue.

Include as much of the following as is safe:

- affected version or commit and platform;
- affected component and configuration;
- impact and the security boundary that was crossed;
- minimal reproduction steps or a sanitized reproducer;
- relevant logs with tokens, paths, and target data removed;
- whether the issue involves host execution, sandbox escape, API exposure,
  filesystem scope, provider credentials, or automotive traffic;
- any suggested mitigation or embargo constraints.

Maintainers will triage the report and coordinate validation, remediation, and
disclosure. This project does not promise a fixed response SLA; severity,
reproducibility, and maintainer availability affect timing.

## High-priority report areas

- generated harnesses, engines, or crash inputs executing outside `hf-runtime`;
- sandbox escape, unsafe mounts, network access, or resource-limit bypass;
- missing or bypassable human promotion and guardrail checks;
- REST authentication, CORS, project-root, or path traversal failures;
- secrets exposed in logs, exports, reports, diagnostics, or the desktop UI;
- dependency or release-artifact tampering;
- automotive operations that exceed offline/vcan policy, exact allowlists, or
  fresh plan-scoped approval.

## Safe research expectations

Test only systems and targets you own or are explicitly authorized to assess.
Use deterministic fixtures and sandboxed environments. Do not test against
production services, public networks, physical vehicle interfaces, or third
party data without written authorization. Stop if a test risks availability,
privacy, or safety.

Human approval in hobot_fuzz authorizes only the bounded sandboxed action shown
to the operator. It does not authorize host execution or activity outside the
approved target and environment.
