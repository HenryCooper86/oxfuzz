'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const test = require('node:test');

const buildScript = path.resolve(__dirname, '../build-app.sh');

function executable(file, body) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, `#!/bin/sh\n${body}\n`, { mode: 0o755 });
}

function buildWithPlatform(version, configuredStrip, withApp = false) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'oxfuzz-build-app-'));
  try {
    const script = path.join(root, 'scripts/build-app.sh');
    fs.mkdirSync(path.dirname(script), { recursive: true });
    fs.copyFileSync(buildScript, script);
    const commands = path.join(root, 'commands');
    executable(path.join(commands, 'uname'), 'case "$1" in -s) echo Darwin;; -m) echo arm64;; esac');
    executable(path.join(commands, 'sw_vers'), `echo ${version}`);
    executable(path.join(commands, 'npm'), 'exit 0');
    executable(path.join(commands, 'hdiutil'), 'exit 0');
    executable(path.join(commands, 'codesign'), [
      'if [ "$1" = "--force" ]; then',
      '  for last_arg; do :; done',
      '  printf "resigned" >> "$last_arg/Contents/MacOS/hf-gui"',
      'fi',
    ].join('\n'));
    executable(path.join(commands, 'xattr'), 'exit 0');
    executable(path.join(root, 'crates/hf-gui/node_modules/.bin/tauri'), [
      'printf "%s" "${CARGO_PROFILE_RELEASE_STRIP-unset}" > "$CAPTURE"',
      'mkdir -p ../../target/release/bundle/dmg',
      ...(withApp ? [
        'mkdir -p ../../target/release/bundle/macos/oxfuzz.app/Contents/MacOS',
        'printf "signed-by-tauri" > ../../target/release/bundle/macos/oxfuzz.app/Contents/MacOS/hf-gui',
        'cp ../../target/release/bundle/macos/oxfuzz.app/Contents/MacOS/hf-gui ../../target/release/bundle/dmg/oxfuzz_0.5.1_aarch64.dmg',
      ] : ['touch ../../target/release/bundle/dmg/oxfuzz_0.5.1_aarch64.dmg']),
    ].join('\n'));
    const capture = path.join(root, 'strip-value');
    const env = {
      ...process.env,
      PATH: `${commands}:${process.env.PATH}`,
      CAPTURE: capture,
      HF_SKIP_DEFECTDOJO: '1',
    };
    delete env.CARGO_PROFILE_RELEASE_STRIP;
    if (configuredStrip !== undefined) env.CARGO_PROFILE_RELEASE_STRIP = configuredStrip;
    const result = spawnSync('bash', [script], { env, encoding: 'utf8' });
    assert.equal(result.status, 0, result.stderr || result.stdout);
    return {
      strip: fs.readFileSync(capture, 'utf8'),
      appBinary: withApp ? fs.readFileSync(path.join(root, 'target/release/bundle/macos/oxfuzz.app/Contents/MacOS/hf-gui'), 'utf8') : null,
      dmgCopy: withApp ? fs.readFileSync(path.join(root, 'target/release/bundle/dmg/oxfuzz_0.5.1_aarch64.dmg'), 'utf8') : null,
    };
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
}

test('macOS 27 release build retains proc-macro symbols for the system loader', () => {
  assert.equal(buildWithPlatform('27.0').strip, 'none');
});

test('earlier macOS build keeps its normal Cargo release profile', () => {
  assert.equal(buildWithPlatform('26.0').strip, 'unset');
});

test('an explicit Cargo strip setting takes precedence', () => {
  assert.equal(buildWithPlatform('27.0', 'symbols').strip, 'symbols');
});

test('standalone app stays identical to the app packaged by Tauri', () => {
  const bundle = buildWithPlatform('27.0', undefined, true);
  assert.equal(bundle.appBinary, bundle.dmgCopy);
});
