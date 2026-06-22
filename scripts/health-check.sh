#!/usr/bin/env bash
# hobot_fuzz -- health check
# Verifies engine binaries and provider config are present.
set -euo pipefail

echo "hobot_fuzz health check"
echo "------------------------"

check_bin() {
    if command -v "$1" >/dev/null 2>&1; then
        echo "OK  $1 -> $(command -v "$1")"
    else
        echo "MISSING  $1"
    fi
}

check_bin afl-fuzz
check_bin honggfuzz
check_bin clang
check_bin cargo
check_bin docker

if [ -f config/providers.toml ]; then
    echo "OK  config/providers.toml"
else
    echo "MISSING  config/providers.toml (run: hobot-fuzz init)"
fi

if [ -f config/engines.toml ]; then
    echo "OK  config/engines.toml"
else
    echo "MISSING  config/engines.toml"
fi

echo "Done."