'use strict';

const CI_WORKFLOW = 'ci.yml';
const CI_POLL_MS = 30_000;
const CI_MAX_POLLS = 60;
const pause = milliseconds => new Promise(resolve => setTimeout(resolve, milliseconds));

function newestPushRun(runs, sha, branch) {
  const candidates = runs.filter(run => run.head_sha === sha && run.event === 'push' &&
    (branch === undefined || run.head_branch === branch));
  for (const run of candidates) {
    if (['id', 'run_number', 'run_attempt'].some(field =>
      !Number.isSafeInteger(run[field]) || run[field] < 1)) {
      throw new Error('candidate CI run identity is invalid');
    }
  }
  return candidates.sort((left, right) =>
    right.run_number - left.run_number || right.run_attempt - left.run_attempt)[0];
}

async function latestCandidateRun(github, repo, sha, branch) {
  const { data } = await github.rest.actions.listWorkflowRuns({
    ...repo, workflow_id: CI_WORKFLOW, head_sha: sha, per_page: 100,
  });
  return newestPushRun(data.workflow_runs, sha, branch);
}

function requireSameSuccessfulRun(current, expected) {
  if (!current || current.id !== expected.id || current.run_attempt !== expected.run_attempt ||
      current.status !== 'completed' || current.conclusion !== 'success') {
    throw new Error('candidate CI changed after validation; review the latest run before proceeding');
  }
}

async function requirePassedGate(github, repo, run, branch) {
  if (run.status !== 'completed' || run.conclusion !== 'success') {
    throw new Error(`candidate CI failed or did not complete successfully in run ${run.id}`);
  }
  const { data: result } = await github.rest.actions.listJobsForWorkflowRunAttempt({
    ...repo, run_id: run.id, attempt_number: run.run_attempt, per_page: 100,
  });
  const gates = result.jobs.filter(job => job.name === 'All gates passed');
  if (gates.length !== 1 || gates[0].status !== 'completed' || gates[0].conclusion !== 'success' ||
      gates[0].run_id !== run.id || gates[0].run_attempt !== run.run_attempt ||
      gates[0].head_sha !== run.head_sha) {
    throw new Error(`candidate CI required gate failed or is missing in run ${run.id}`);
  }
  const current = await latestCandidateRun(github, repo, run.head_sha, branch);
  requireSameSuccessfulRun(current, run);
}

async function waitForCandidateCi({ github, repo, sha, attempts = CI_MAX_POLLS, sleep = pause, branch }) {
  if (!Number.isInteger(attempts) || attempts < 1) {
    throw new Error('CI poll count must be positive');
  }
  for (let attempt = 0; attempt < attempts; attempt += 1) {
    const run = await latestCandidateRun(github, repo, sha, branch);
    if (run?.status === 'completed') {
      await requirePassedGate(github, repo, run, branch);
      return run;
    }
    if (attempt + 1 < attempts) {
      await sleep(CI_POLL_MS);
    }
  }
  throw new Error(`candidate CI did not complete successfully for ${sha}`);
}

async function requireSameLatestCi(github, repo, sha, expected, branch) {
  const current = await latestCandidateRun(github, repo, sha, branch);
  requireSameSuccessfulRun(current, expected);
  await requirePassedGate(github, repo, current, branch);
}

module.exports = { CI_MAX_POLLS, waitForCandidateCi, requireSameLatestCi };
