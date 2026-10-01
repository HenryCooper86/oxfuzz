'use strict';
const assert = require('node:assert/strict');
const test = require('node:test');
const { inspectPerformanceCandidate, recheckPerformanceCandidate } = require('../performance_candidate.cjs');
const SHA = 'a'.repeat(40);
const context = { eventName: 'workflow_dispatch', ref: 'refs/heads/main', sha: SHA, repo: { owner: 'example', repo: 'oxfuzz' } };
const run = overrides => ({ id: 7, run_number: 7, run_attempt: 1, head_sha: SHA, head_branch: 'main', event: 'push', status: 'completed', conclusion: 'success', html_url: 'https://github.com/example/oxfuzz/actions/runs/7', ...overrides });
function gateJob(overrides = {}) {
  return { name: 'All gates passed', status: 'completed', conclusion: 'success',
    run_id: 7, run_attempt: 1, head_sha: SHA, ...overrides };
}
function api(runs = [run()], jobs = [gateJob()], afterJobs) {
  let reads = 0;
  function readJobs(args) {
    assert.equal(args.run_id, 7);
    assert.equal(args.attempt_number, 1);
    if (afterJobs) runs = afterJobs;
    return { data: { jobs } };
  }
  return {
    reads: () => reads,
    rest: { actions: {
      listWorkflowRuns: async args => {
        reads++;
        assert.equal(args.workflow_id, 'ci.yml'); assert.equal(args.head_sha, SHA);
        return { data: { workflow_runs: runs } };
      },
      listJobsForWorkflowRunAttempt: async args => readJobs(args),
    } },
  };
}
test('diagnostics admit an exact successful main push and retain its identity', async () => {
  const result = await inspectPerformanceCandidate({ github: api(), context });
  assert.deepEqual(result, { schema_version: 1, candidate_commit: SHA, ci_run_id: 7, ci_run_attempt: 1, ci_url: 'https://github.com/example/oxfuzz/actions/runs/7' });
});
test('non-main or non-manual events fail before querying CI', async () => {
  for (const change of [{ ref: 'refs/heads/topic' }, { ref: 'refs/tags/v0.5.1' }, { eventName: 'push' }, { sha: 'bad' }]) {
    const github = api();
    await assert.rejects(inspectPerformanceCandidate({ github, context: { ...context, ...change } }));
    assert.equal(github.reads(), 0);
  }
});
test('pending, failed, missing, foreign or superseded CI cannot admit diagnostics', async () => {
  for (const runs of [[], [run({ status: 'in_progress', conclusion: null })], [run({ conclusion: 'failure' })], [run({ head_sha: 'b'.repeat(40) })], [run({ event: 'pull_request' })], [run({ head_branch: 'topic' })], [run(), run({ id: 8, run_number: 8, conclusion: 'cancelled' })]]) {
    await assert.rejects(inspectPerformanceCandidate({ github: api(runs), context }), /CI/);
  }
});
test('the required aggregate job must itself be completed and successful', async () => {
  for (const jobs of [[], [{ name: 'All gates passed', status: 'completed', conclusion: 'skipped' }], [{ name: 'All gates passed', status: 'in_progress', conclusion: null }]]) {
    await assert.rejects(inspectPerformanceCandidate({ github: api([run()], jobs), context }), /CI/);
  }
});
test('the post-build check denies reruns, replacement runs and failed conclusions', async () => {
  const receipt = await inspectPerformanceCandidate({ github: api(), context });
  await recheckPerformanceCandidate({ github: api(), context, receipt });
  for (const runs of [[run({ run_attempt: 2 })], [run({ id: 8, run_number: 8 })], [run({ conclusion: 'failure' })]]) {
    await assert.rejects(recheckPerformanceCandidate({ github: api(runs), context, receipt }), /CI/);
  }
  await assert.rejects(recheckPerformanceCandidate({ github: api(), context, receipt: { ...receipt, candidate_commit: 'b'.repeat(40) } }));
});
test('credential-bearing or insecure CI links are not retained', async () => {
  for (const html_url of ['http://github.com/example/oxfuzz/actions/runs/7', 'https://secret@github.com/example/oxfuzz/actions/runs/7']) {
    await assert.rejects(inspectPerformanceCandidate({ github: api([run({ html_url })]), context }));
  }
});

test('invalid CI run identities cannot be retained as admission evidence', async () => {
  for (const change of [{ id: 0 }, { run_attempt: null }, { run_number: '7' }]) {
    await assert.rejects(inspectPerformanceCandidate({ github: api([run(change)]), context }), /CI/);
  }
});


test('diagnostic recheck refuses aggregate evidence for a different attempt or source', async () => {
  const receipt = await inspectPerformanceCandidate({ github: api(), context });
  for (const change of [{ run_id: 8 }, { run_attempt: 2 }, { head_sha: 'b'.repeat(40) }]) {
    await assert.rejects(recheckPerformanceCandidate({ github: api([run()], [gateJob(change)]), context, receipt }), /CI/);
  }
});

test('diagnostic recheck observes reruns, replacements and failure during its job query', async () => {
  const receipt = await inspectPerformanceCandidate({ github: api(), context });
  for (const change of [{ run_attempt: 2 }, { id: 8, run_number: 8 }, { conclusion: 'failure' }]) {
    await assert.rejects(recheckPerformanceCandidate({ github: api([run()], [gateJob()], [run(change)]), context, receipt }), /CI/);
  }
});
