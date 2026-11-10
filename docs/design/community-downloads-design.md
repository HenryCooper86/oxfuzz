# Community downloads and private source

## Intent and scope

Serve a public oxfuzz download website at `https://oxfuzz.bionicloud.net` on the
owner's existing Lightsail instance. The application repository becomes private;
public downloads must remain usable without GitHub authentication. Retain only
the latest GitHub release and version tag after its replacement is verified.

## Distribution

Publish desktop installers, checksums, release notes, and a sandbox build kit
under versioned, same-origin download paths. The kit contains only the required
Docker build recipe, compiler/scanner verification scripts, Clang helper source,
vendor rule files and license notices; it excludes application crates, Git
history, credentials, databases, corpora and crash artifacts. It builds pinned
third-party tools locally, avoiding distribution of a prebuilt GPL tool image.

Build the website from a manifest generated from the actual release files.
Published manifests require valid versions, supported asset names, byte counts
and SHA-256 digests. Missing assets fail the build. A local candidate preview
shows unavailable downloads as disabled; it must never invent download links or
checksums. Download URLs are same-origin paths, not private GitHub release URLs.

Use the existing host's web server and TLS configuration when possible. Inspect
its services before deploying. Stage a complete site in a new directory, verify
files and configuration, then switch its dedicated virtual host atomically.
Preserve unrelated sites. Never expose SSH keys or GitHub tokens to the browser.
Verify anonymous HTTPS page and file access before changing repository visibility.

## Website

The primary audience is developers and security researchers installing the
workbench. Provide a brief product explanation, platform downloads, clear
experimental signing status, Docker/setup requirements, release changes and
SHA-256 verification instructions. Do not advertise unsupported workflows or
link visitors to documentation they cannot read after the repository is private.
No account system, analytics, newsletter form, or payment flow is needed.
Explain implemented advantages: candidate ranking, harness qualification, visible
assistant tool calls, provider routing/failover and spending limits, crash triage,
corpus management, project knowledge, reusable skills, configurable agents,
reviewed finding handoff and authorized scheduling. Sources are the
README capability table, embedded Help and provider/settings implementations.
Provider availability depends on endpoint credentials and model capabilities;
rankings and generated reports remain reviewable suggestions.
Compare direct engine use with oxfuzz by workflow task. Acknowledge upstream
monitoring, corpus and triage tools, link primary documentation, and avoid
performance claims without controlled measurements.
The desktop Help and About links point to this public website and its setup
section. Embedded help remains available offline; external documentation must
not require access to the private source repository.

Visual decisions: match the application tokens. Dark mode uses charcoal #0f0f0f,
secondary surfaces #141414, warm text #e8e6e1 and gold #c8b560. Light mode uses
white, warm gray #f5f4f1, text #1a1917 and gold #9a7c2a. Use the application's
system sans-serif stack, large restrained typography and thin separators.
Green (#6fcf97 dark, #397a52 light) marks isolation and retained-evidence
capabilities; gold remains the action and selection color.
Lead with an actual application screenshot; a three-view gallery shows the
qualification example's dashboard, harness review and run history. Captions
identify real test data, without suggesting benchmark results. Keep downloads
in horizontal platform rows and stack content on small screens. Clip native
screenshot corners proportionally to their original window radius, concealing
outside-window pixels without trimming the interface.

A single icon button cycles Dark, Light, System, matching the desktop app.
Default to System. Persist the preference when local storage is available;
System follows live OS appearance changes. Use accessible current/next names,
visible keyboard focus, and a small same-origin script allowed by the CSP.
The gallery uses ordinary buttons with pressed states and works with keyboard
activation. Without JavaScript the first screenshot and all downloads remain
usable, with CSS following the system color scheme.

## Verification

Test the manifest checks against missing files, unsupported names, invalid
checksums and external/private download URLs. Inspect desktop and mobile layouts
and keyboard navigation. Verify downloaded bytes against the manifest. Reconcile
release/tag deletion against the backed-up inventory. Verify private source
visibility and anonymous website/download access after the transition.

Assumptions: public distribution means application binaries and the minimal
sandbox build kit, not the application source tree. Version 0.9.4 is the next
unused patch release. macOS builds remain ad-hoc signed and unnotarized; Windows
builds remain unsigned unless a signing identity is supplied.
