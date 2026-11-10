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
The desktop Help and About links point to this public website and its setup
section. Embedded help remains available offline; external documentation must
not require access to the private source repository.

Visual decisions: white and pale blue surfaces (#ffffff, #f2f5f8), navy text
(#101b2b), secondary slate (#43536a), muted gold from the application (#d1b350),
and cool gray rules (#d7dfe8). Use Avenir Next/Segoe UI for interface text and a
system monospace face only for commands and checksums. A large left-aligned
headline and a compact target-to-triage workflow diagram introduce the product;
platform downloads form clear horizontal groups rather than a grid of marketing
cards. Keep widths comfortable, focus states visible, and mobile layouts stacked.

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
