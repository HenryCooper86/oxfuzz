#!/usr/bin/env bash
# Linux system dependencies for building the workspace.
#
# crates/hf-gui/src-tauri is a workspace member and Cargo.toml declares no
# default-members, so every `--workspace` cargo command builds it. On Linux that
# means webkit2gtk-sys, javascriptcore-rs-sys, soup3-sys and gtk-sys, whose
# build scripts fail without these packages. macOS needs none of this: Tauri
# uses WKWebView there, which is why the gap was invisible during development.
#
# release.yml installs the same list for its Linux bundle job. Keep them in step.
set -euo pipefail

SUDO=""
if [ "$(id -u)" -ne 0 ]; then
  SUDO="sudo"
fi

${SUDO} apt-get update
${SUDO} apt-get install -y \
  libwebkit2gtk-4.1-dev \
  libappindicator3-dev \
  librsvg2-dev \
  patchelf \
  build-essential \
  file \
  libssl-dev \
  libxdo-dev \
  libsoup-3.0-dev
