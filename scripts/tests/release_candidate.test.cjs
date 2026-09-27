'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');
const {
  acceptanceTemplate, inspectReleaseCandidate, publishReleaseCandidate, validateReleaseStart,
} = require('../release_candidate.cjs');

const SHA = 'a'.repeat(40);
const VERSION = '0.5.2';
const TAG = `v${VERSION}`;
const DIGEST = `sha256:${'b'.repeat(64)}`;

function acceptanceBody(overrides = {}) {
  const references = Object.fromEntries([
    'userspace_engines', 'sandbox_isolation', 'installed_clients',
  ].map(claim => [claim, { url: `https://example.org/evidence/${claim}`, sha256: DIGEST }]));
  const record = { candidate_commit: SHA, scope: Object.keys(references), references, ...overrides };
  return `Release notes\n\n<!-- oxfuzz-release-acceptance\n${JSON.stringify(record)}\n-->`;
}

function candidateDirectory() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'oxfuzz-release-'));
  fs.mkdirSync(path.join(root, 'crates/hf-gui/src-tauri'), { recursive: true });
  fs.writeFileSync(path.join(root, 'Cargo.toml'), '[workspace.package]\nversion = "0.5.2"\n');
  fs.writeFileSync(path.join(root, 'crates/hf-gui/package.json'), '{"version":"0.5.2"}');
  fs.writeFileSync(path.join(root, 'crates/hf-gui/src-tauri/tauri.conf.json'), '{"version":"0.5.2"}');
  return root;
}

function assets() {
  return [
    `oxfuzz_${VERSION}_aarch64.dmg`,
    `oxfuzz_${VERSION}_x64.dmg`,
    `oxfuzz_${VERSION}_amd64.AppImage`,
    `oxfuzz_${VERSION}_amd64.deb`,
    `oxfuzz-${VERSION}-1.x86_64.rpm`,
    `oxfuzz_${VERSION}_x64_en-US.msi`,
    `oxfuzz_${VERSION}_x64-setup.exe`,
  ].map(name => ({ name, size: 123, state: 'uploaded', digest: DIGEST }));
}

function ciRun(overrides = {}) {
  return {
    id: 7, run_number: 7, run_attempt: 1, head_sha: SHA, event: 'push',
    status: 'completed', conclusion: 'success', html_url: 'https://github.com/example/oxfuzz/actions/runs/7',
    ...overrides,
  };
}

function fakeGithub({
  runs = [[ciRun()]], release = {}, releaseAssets = assets(), tagCommit = SHA,
  jobs = [{ name: 'All gates passed', status: 'completed', conclusion: 'success' }],
  jobsByRun = {},
} = {}) {
  let ciReads = 0;
  const updates = [];
  const github = {
    rest: {
      repos: {
        getCommit: async ({ ref }) => {
          assert.equal(ref, TAG);
          return { data: { sha: tagCommit } };
        },
        getRelease: async ({ release_id }) => {
          assert.equal(release_id, 42);
          return { data: { draft: true, tag_name: TAG, body: acceptanceBody(), ...release } };
        },
        listReleaseAssets: () => {},
        updateRelease: async request => {
          updates.push(request);
          return { data: { html_url: 'https://github.com/example/oxfuzz/releases/tag/v0.5.2' } };
        },
      },
      actions: {
        listWorkflowRuns: async ({ workflow_id, head_sha, per_page }) => {
          assert.equal(workflow_id, 'ci.yml');
          assert.equal(head_sha, SHA);
          assert.equal(per_page, 100);
          const entry = runs[Math.min(ciReads++, runs.length - 1)];
          if (entry instanceof Error) throw entry;
          return { data: { workflow_runs: entry } };
        },
        listJobsForWorkflowRun: async ({ run_id, per_page, filter }) => {
          assert.ok([7, 8].includes(run_id));
          assert.equal(per_page, 100);
          assert.equal(filter, 'latest');
          return { data: { jobs: jobsByRun[run_id] ?? jobs } };
        },
      },
    },
    paginate: async (_method, { release_id }) => {
      assert.equal(release_id, 42);
      return releaseAssets;
    },
  };
  return { github, updates, ciReads: () => ciReads };
}

function context(overrides = {}) {
  return {
    eventName: 'push', ref: `refs/tags/${TAG}`, sha: SHA,
    repo: { owner: 'example', repo: 'oxfuzz' }, ...overrides,
  };
}

async function run(root, fake, options = {}) {
  return publishReleaseCandidate({
    github: fake.github, context: context(options.context), releaseId: 42,
    root, attempts: options.attempts ?? 2, sleep: async () => {},
  });
}

function withCandidate(fn) {
  const root = candidateDirectory();
  return Promise.resolve().then(() => fn(root)).finally(() => fs.rmSync(root, { recursive: true, force: true }));
}

test('publishes only a complete candidate and records CI and asset digests', () => withCandidate(async root => {
  const fake = fakeGithub();
  const result = await run(root, fake);
  assert.equal(result.ciRunId, 7);
  assert.equal(fake.updates.length, 1);
  assert.equal(fake.updates[0].draft, false);
  assert.match(fake.updates[0].body, /actions\/runs\/7/);
  assert.match(fake.updates[0].body, /oxfuzz_0\.5\.2_aarch64\.dmg.*sha256:/);
  assert.match(fake.updates[0].body, new RegExp(SHA));
  assert.match(fake.updates[0].body, /evidence\/userspace_engines/);
  assert.match(fake.updates[0].body, /Signing and notarization status: unsigned and not notarized/);
}));

test('inspection returns a reviewable record without publishing', () => withCandidate(async root => {
  const fake = fakeGithub();
  const record = await inspectReleaseCandidate({
    github: fake.github, context: context(), releaseId: 42, root,
    attempts: 2, sleep: async () => {},
  });
  assert.equal(record.ciRunId, 7);
  assert.equal(record.assets.length, 7);
  assert.equal(record.acceptance.scope.length, 3);
  assert.equal(fake.updates.length, 0);
}));

test('an unedited acceptance template cannot publish a release', () => withCandidate(async root => {
  const fake = fakeGithub({ release: { body: `Release notes\n${acceptanceTemplate(SHA)}` } });
  await assert.rejects(run(root, fake), /acceptance/);
  assert.equal(fake.updates.length, 0);
}));

test('missing or mismatched acceptance evidence keeps the release draft', () => withCandidate(async root => {
  const missing = fakeGithub({ release: { body: 'Release notes' } });
  await assert.rejects(run(root, missing), /acceptance/);
  assert.equal(missing.updates.length, 0);

  for (const record of [
    { candidate_commit: 'c'.repeat(40) },
    { scope: ['userspace_engines'] },
    { references: { userspace_engines: { url: 'http://example.org/report', sha256: DIGEST } } },
  ]) {
    const fake = fakeGithub({ release: { body: acceptanceBody(record) } });
    await assert.rejects(run(root, fake), /acceptance/);
    assert.equal(fake.updates.length, 0);
  }
}));

test('rejects branch dispatch before creating a draft', () => withCandidate(async root => {
  const fake = fakeGithub();
  await assert.rejects(validateReleaseStart({
    github: fake.github, context: context({ eventName: 'workflow_dispatch', ref: 'refs/heads/main' }), root,
  }), /version tag/);
  assert.equal(fake.updates.length, 0);
}));

test('rejects version manifests that disagree with the tag', () => withCandidate(async root => {
  fs.writeFileSync(path.join(root, 'crates/hf-gui/package.json'), '{"version":"0.5.1"}');
  const fake = fakeGithub();
  await assert.rejects(run(root, fake), /version/);
  assert.equal(fake.updates.length, 0);
}));

test('rejects a moved or mismatched tag', () => withCandidate(async root => {
  const fake = fakeGithub({ tagCommit: 'c'.repeat(40) });
  await assert.rejects(run(root, fake), /tag.*commit/);
  assert.equal(fake.updates.length, 0);
}));

test('rejects a release associated with another tag or already public', () => withCandidate(async root => {
  for (const release of [{ tag_name: 'v0.5.1' }, { draft: false }]) {
    const fake = fakeGithub({ release });
    await assert.rejects(run(root, fake), /release.*tag|draft/);
    assert.equal(fake.updates.length, 0);
  }
}));

test('waits for a pending CI run on the candidate commit', () => withCandidate(async root => {
  const fake = fakeGithub({ runs: [
    [ciRun({ status: 'in_progress', conclusion: null })],
    [ciRun()],
  ] });
  await run(root, fake);
  assert.equal(fake.ciReads(), 4);
  assert.equal(fake.updates.length, 1);
}));

test('a CI rerun queued after installer inspection blocks publication', () => withCandidate(async root => {
  const fake = fakeGithub({ runs: [
    [ciRun()],
    [ciRun(), ciRun({ id: 8, run_number: 8, status: 'queued', conclusion: null })],
  ] });
  await assert.rejects(run(root, fake), /CI changed/);
  assert.equal(fake.updates.length, 0);
}));

test('rejects a tag moved while CI was pending', () => withCandidate(async root => {
  const fake = fakeGithub({ runs: [
    [ciRun({ status: 'in_progress', conclusion: null })],
    [ciRun()],
  ] });
  let tagReads = 0;
  fake.github.rest.repos.getCommit = async () => ({
    data: { sha: tagReads++ === 0 ? SHA : 'c'.repeat(40) },
  });
  await assert.rejects(run(root, fake), /tag.*commit/);
  assert.equal(fake.updates.length, 0);
}));

test('rejects an incomplete CI run after the wait limit', () => withCandidate(async root => {
  const fake = fakeGithub({ runs: [[ciRun({ status: 'queued', conclusion: null })]] });
  await assert.rejects(run(root, fake), /CI.*did not complete/);
  assert.equal(fake.ciReads(), 2);
  assert.equal(fake.updates.length, 0);
}));

test('rejects missing CI and a failed CI run', () => withCandidate(async root => {
  for (const fixture of [
    { runs: [[]] },
    { runs: [[ciRun({ conclusion: 'failure' })]], jobs: [
      { name: 'All gates passed', status: 'completed', conclusion: 'failure' },
    ] },
  ]) {
    const fake = fakeGithub(fixture);
    await assert.rejects(run(root, fake), /CI/);
    assert.equal(fake.updates.length, 0);
  }
}));

test('a completed workflow without a successful required gate stays draft', () => withCandidate(async root => {
  for (const jobs of [
    [],
    [{ name: 'All gates passed', status: 'completed', conclusion: 'skipped' }],
  ]) {
    const fake = fakeGithub({ jobs });
    await assert.rejects(run(root, fake), /CI/);
    assert.equal(fake.updates.length, 0);
  }
}));

test('a newer failed run blocks an older success on the same commit', () => withCandidate(async root => {
  const fake = fakeGithub({ runs: [[
    ciRun({ id: 7, run_number: 7 }),
    ciRun({ id: 8, run_number: 8, conclusion: 'failure' }),
  ]], jobsByRun: { 8: [
    { name: 'All gates passed', status: 'completed', conclusion: 'failure' },
  ] } });
  await assert.rejects(run(root, fake), /CI.*fail/);
  assert.equal(fake.updates.length, 0);
}));

test('ignores CI results from another commit and pull requests', () => withCandidate(async root => {
  const fake = fakeGithub({ runs: [[
    ciRun({ head_sha: 'd'.repeat(40), run_number: 9 }),
    ciRun({ event: 'pull_request', run_number: 10 }),
  ]] });
  await assert.rejects(run(root, fake), /CI.*did not complete/);
  assert.equal(fake.updates.length, 0);
}));

test('rejects a missing, empty, or unhashed installer', () => withCandidate(async root => {
  for (const releaseAssets of [
    assets().filter(asset => !asset.name.endsWith('.msi')),
    assets().map(asset => asset.name.endsWith('.msi') ? { ...asset, size: 0 } : asset),
    assets().map(asset => asset.name.endsWith('.msi') ? { ...asset, digest: null } : asset),
  ]) {
    const fake = fakeGithub({ releaseAssets });
    await assert.rejects(run(root, fake), /asset|installer|digest/);
    assert.equal(fake.updates.length, 0);
  }
}));

test('GitHub API errors keep the release draft', () => withCandidate(async root => {
  const fake = fakeGithub({ runs: [[new Error('API unavailable')]] });
  fake.github.rest.actions.listWorkflowRuns = async () => { throw new Error('API unavailable'); };
  await assert.rejects(run(root, fake), /API unavailable/);
  assert.equal(fake.updates.length, 0);
}));
