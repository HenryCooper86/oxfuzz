'use strict';

const { waitForCandidateCi, requireSameLatestCi } = require('./source_ci.cjs');

function validateStart(context) {
  if (context.eventName !== 'workflow_dispatch' || context.ref !== 'refs/heads/main' ||
      !/^[0-9a-f]{40}$/.test(context.sha)) {
    throw new Error('performance diagnostics require a manual dispatch on a full main commit');
  }
}

function checkedUrl(value) {
  const url = new URL(value);
  if (url.protocol !== 'https:' || url.username || url.password) {
    throw new Error('CI link must use HTTPS without credentials');
  }
  return url.href;
}

async function inspectPerformanceCandidate({ github, context }) {
  validateStart(context);
  const run = await waitForCandidateCi({
    github, repo: context.repo, sha: context.sha, branch: 'main', attempts: 1,
  });
  return {
    schema_version: 1, candidate_commit: context.sha,
    ci_run_id: run.id, ci_run_attempt: run.run_attempt, ci_url: checkedUrl(run.html_url),
  };
}

async function recheckPerformanceCandidate({ github, context, receipt }) {
  validateStart(context);
  if (receipt?.schema_version !== 1 || receipt.candidate_commit !== context.sha ||
      !Number.isSafeInteger(receipt.ci_run_id) || receipt.ci_run_id < 1 ||
      !Number.isSafeInteger(receipt.ci_run_attempt) || receipt.ci_run_attempt < 1) {
    throw new Error('CI receipt does not identify this performance candidate');
  }
  checkedUrl(receipt.ci_url);
  await requireSameLatestCi(github, context.repo, context.sha, {
    id: receipt.ci_run_id, run_attempt: receipt.ci_run_attempt,
  }, 'main');
}

module.exports = { inspectPerformanceCandidate, recheckPerformanceCandidate };
