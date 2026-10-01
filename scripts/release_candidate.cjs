'use strict';

const fs = require('node:fs');
const path = require('node:path');

const { CI_MAX_POLLS, waitForCandidateCi, requireSameLatestCi } = require('./source_ci.cjs');
const REQUIRED_CLAIMS = ['userspace_engines', 'sandbox_isolation', 'installed_clients'];
const OPTIONAL_CLAIMS = [
  'syzkaller', 'automotive_virtual_lab', 'automotive_physical_lab', 'finding_publication',
];

function candidateVersion(root, tag) {
  if (!/^v\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/.test(tag)) {
    throw new Error(`release ref must be a version tag: ${tag}`);
  }
  const version = tag.slice(1);
  const cargo = fs.readFileSync(path.join(root, 'Cargo.toml'), 'utf8');
  const workspace = cargo.match(/^\[workspace\.package\]\s*\nversion\s*=\s*"([^"]+)"/m);
  const gui = JSON.parse(fs.readFileSync(path.join(root, 'crates/hf-gui/package.json'), 'utf8'));
  const tauri = JSON.parse(fs.readFileSync(path.join(root, 'crates/hf-gui/src-tauri/tauri.conf.json'), 'utf8'));
  if (!workspace || [workspace[1], gui.version, tauri.version].some(value => value !== version)) {
    throw new Error(`release version ${version} does not match all workspace and desktop manifests`);
  }
  return version;
}

async function validateReleaseStart({ github, context, root }) {
  const { eventName, ref, sha, repo } = context;
  if (!['push', 'workflow_dispatch'].includes(eventName) || !ref?.startsWith('refs/tags/')) {
    throw new Error('release must start from a version tag push or tag dispatch');
  }
  const tag = ref.slice('refs/tags/'.length);
  const version = candidateVersion(root, tag);
  if (!/^[0-9a-f]{40}$/.test(sha)) {
    throw new Error('release candidate commit must be a full SHA-1');
  }
  const { data: commit } = await github.rest.repos.getCommit({ ...repo, ref: tag });
  if (commit.sha !== sha) {
    throw new Error(`release tag ${tag} no longer points to candidate commit ${sha}`);
  }
  return { tag, version, sha };
}

function acceptanceTemplate(sha) {
  const references = Object.fromEntries(REQUIRED_CLAIMS.map(claim => [
    claim, { url: '', sha256: '' },
  ]));
  return `<!-- oxfuzz-release-acceptance\n${JSON.stringify({
    candidate_commit: sha, scope: REQUIRED_CLAIMS, references,
  }, null, 2)}\n-->`;
}

function checkedAcceptance(body, sha) {
  const matches = [...body.matchAll(/<!-- oxfuzz-release-acceptance\s*\n([\s\S]*?)\n-->/g)];
  if (matches.length !== 1) {
    throw new Error('release acceptance record is missing or duplicated');
  }
  let record;
  try {
    record = JSON.parse(matches[0][1]);
  } catch {
    throw new Error('release acceptance record is not valid JSON');
  }
  if (record?.candidate_commit !== sha || !Array.isArray(record.scope) ||
      !REQUIRED_CLAIMS.every(claim => record.scope.includes(claim)) ||
      record.scope.length !== new Set(record.scope).size ||
      !record.scope.every(claim => [...REQUIRED_CLAIMS, ...OPTIONAL_CLAIMS].includes(claim)) ||
      !record.references || typeof record.references !== 'object') {
    throw new Error('release acceptance scope or candidate commit is invalid');
  }
  for (const claim of record.scope) {
    const reference = record.references[claim];
    let url;
    try {
      url = new URL(reference?.url);
    } catch {
      throw new Error(`release acceptance URL is missing for ${claim}`);
    }
    if (url.protocol !== 'https:' || url.username || url.password ||
        !/^sha256:[0-9a-f]{64}$/.test(reference.sha256 ?? '')) {
      throw new Error(`release acceptance reference is invalid for ${claim}`);
    }
  }
  return record;
}

function requiredAssetNames(version) {
  return [
    `oxfuzz_${version}_aarch64.dmg`,
    `oxfuzz_${version}_x64.dmg`,
    `oxfuzz_${version}_amd64.AppImage`,
    `oxfuzz_${version}_amd64.deb`,
    `oxfuzz-${version}-1.x86_64.rpm`,
    `oxfuzz_${version}_x64_en-US.msi`,
    `oxfuzz_${version}_x64-setup.exe`,
  ];
}

function checkedAssets(assets, version) {
  return requiredAssetNames(version).map(name => {
    const matches = assets.filter(asset => asset.name === name);
    if (matches.length !== 1) {
      throw new Error(`required release asset ${name} is missing or duplicated`);
    }
    const [asset] = matches;
    if (asset.state !== 'uploaded' || !Number.isSafeInteger(asset.size) || asset.size < 1) {
      throw new Error(`required release asset ${name} is empty or not uploaded`);
    }
    if (!/^sha256:[0-9a-f]{64}$/.test(asset.digest ?? '')) {
      throw new Error(`required release asset ${name} has no SHA-256 digest`);
    }
    return asset;
  });
}

async function inspectReleaseCandidate({
  github, context, releaseId, root, attempts = CI_MAX_POLLS, sleep,
}) {
  const { tag, version, sha } = await validateReleaseStart({ github, context, root });
  const repo = context.repo;
  const { data: release } = await github.rest.repos.getRelease({ ...repo, release_id: releaseId });
  if (release.tag_name !== tag) {
    throw new Error(`release tag ${release.tag_name} does not match candidate tag ${tag}`);
  }
  if (!release.draft) {
    throw new Error('release must still be a draft before publication');
  }
  const acceptance = checkedAcceptance(release.body ?? '', sha);
  const run = await waitForCandidateCi({ github, repo, sha, attempts, sleep });
  // CI may take time; do not publish if the tag moved while the job waited.
  await validateReleaseStart({ github, context, root });
  const assets = checkedAssets(await github.paginate(
    github.rest.repos.listReleaseAssets, { ...repo, release_id: releaseId, per_page: 100 },
  ), version);
  await requireSameLatestCi(github, repo, sha, run);
  const validation = [
    '### Candidate validation',
    `- Commit: \`${sha}\``,
    `- Required source CI gate: ${run.html_url}`,
    `- CI run: ${run.id} (attempt ${run.run_attempt}); All gates passed: success`,
    ...assets.map(asset => `- ${asset.name}: \`${asset.digest}\``),
    ...acceptance.scope.map(claim =>
      `- ${claim} acceptance: ${acceptance.references[claim].url} ` +
      `(${acceptance.references[claim].sha256})`),
    '- Signing and notarization status: unsigned and not notarized (no signing secrets configured).',
  ].join('\n');
  const body = `${release.body ?? ''}\n\n${validation}`;
  return {
    tag, sha, ciRunId: run.id, ciRun: run, acceptance,
    assets: assets.map(asset => ({ name: asset.name, digest: asset.digest })), body,
  };
}

async function publishReleaseCandidate(options) {
  const inspection = await inspectReleaseCandidate(options);
  const { github, context, releaseId, root } = options;
  await validateReleaseStart({ github, context, root });
  await requireSameLatestCi(github, context.repo, inspection.sha, inspection.ciRun);
  const { data: published } = await github.rest.repos.updateRelease({
    ...context.repo, release_id: releaseId, body: inspection.body, draft: false,
  });
  return { ciRunId: inspection.ciRunId, url: published.html_url };
}

module.exports = {
  acceptanceTemplate, inspectReleaseCandidate, publishReleaseCandidate, validateReleaseStart,
};
