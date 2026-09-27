#!/usr/bin/env python3
"""Run fixed recovery fault tests with bounded, revision-linked evidence."""

import argparse
import os
from pathlib import Path
import platform
import selectors
import signal
import subprocess
import sys
import time
from typing import NamedTuple

from qualify_engines import persist, revision_identity, timestamp

MAX_LOG_BYTES = 16 * 1024 * 1024


class Scenario(NamedTuple):
    name: str
    command: tuple
    cleanup: str


SCENARIOS = (
    Scenario("journal_process_loss", (
        "cargo", "test", "-p", "hf-service", "--test", "recovery_process",
        "admitted_run_survives_owner_process_loss_and_reconciles_once", "--", "--exact",
    ), "not_applicable"),
    Scenario("closeout_restart", (
        "cargo", "test", "-p", "hf-service", "--test", "run_closeout_service",
        "cancelling_a_closeout_releases_its_lease", "--", "--exact",
    ), "not_applicable"),
    Scenario("one_time_restart", (
        "cargo", "test", "-p", "hf-service", "--lib",
        "scheduler::tests::every_durable_occurrence_state_suppresses_restart_redispatch",
        "--", "--exact",
    ), "not_applicable"),
    Scenario("status_write_failure", (
        "cargo", "test", "-p", "hf-service", "--test", "container",
        "terminal_status_write_failure_still_awaits_monitor_cleanup", "--", "--exact",
    ), "not_applicable"),
    Scenario("runtime_owner_loss", (
        "cargo", "test", "-p", "hf-runtime", "--test", "live_isolation",
        "live_fresh_runtime_removes_a_container_left_by_process_termination",
        "--", "--ignored", "--exact",
    ), "verified_by_test"),
)


def stop_owned_group(process):
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        # The owned group already exited; wait below still reaps its leader.
        pass
    process.wait()


def run_owned_process(command, repo, env, log, timeout):
    """Cap retained output and kill only the subprocess group started here."""
    if os.name != "posix":
        raise ValueError("recovery fault supervision currently requires POSIX")
    with log.open("wb") as stream, selectors.DefaultSelector() as selector:
        process = subprocess.Popen(command, cwd=repo, env=env, stdin=subprocess.DEVNULL,
                                   stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                   start_new_session=True)
        deadline = time.monotonic() + timeout
        written = 0
        try:
            selector.register(process.stdout, selectors.EVENT_READ)
            while selector.get_map() or process.poll() is None:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise subprocess.TimeoutExpired(command, timeout)
                for key, _ in selector.select(min(remaining, 0.1)):
                    chunk = os.read(key.fileobj.fileno(), 8192)
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    keep = min(len(chunk), MAX_LOG_BYTES - written)
                    stream.write(chunk[:keep])
                    written += keep
                    if keep < len(chunk):
                        raise ValueError("worker output limit exceeded")
            stream.flush()
            os.fsync(stream.fileno())
            return process.wait()
        except BaseException:
            stop_owned_group(process)
            raise
        finally:
            process.stdout.close()


def successful_test(log):
    if not log.is_file() or log.is_symlink() or log.stat().st_size > MAX_LOG_BYTES:
        return False
    result = log.read_text(encoding="utf-8", errors="replace")
    return "running 1 test\n" in result and "test result: ok. 1 passed; 0 failed" in result


def run_faults(repo, output, timeout, *, executor=run_owned_process, scenarios=SCENARIOS):
    if os.name != "posix":
        raise ValueError("recovery fault supervision currently requires POSIX")
    if type(timeout) not in (int, float) or not 0 < timeout <= 3600:
        raise ValueError("scenario timeout must be positive and at most 3600 seconds")
    repo, output = Path(repo).resolve(), Path(output).resolve()
    if output == repo or repo in output.parents:
        raise ValueError("recovery evidence must be outside the measured repository")
    identity = revision_identity(repo)
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    manifest_path = output / "manifest.json"
    manifest = {"version": 1, "status": "running", "started_at": timestamp(),
                "revision": identity, "platform": platform.platform(),
                "scenario_timeout_secs": timeout, "cases": []}
    persist(manifest_path, manifest)
    for scenario in scenarios:
        case = {"name": scenario.name, "command": list(scenario.command),
                "status": "running", "cleanup": "unverified", "started_at": timestamp(),
                "log": f"{scenario.name}.log"}
        manifest["cases"].append(case)
        persist(manifest_path, manifest)
        started = time.monotonic()
        try:
            if revision_identity(repo) != identity:
                raise ValueError("repository changed before fault case")
            env = dict(os.environ, CARGO_TERM_COLOR="never")
            code = executor(list(scenario.command), repo, env, output / case["log"], timeout)
            case["exit_code"] = code
            if code != 0:
                raise ValueError(f"fault test exited with status {code}")
            if revision_identity(repo) != identity:
                raise ValueError("repository changed during fault case")
            if not successful_test(output / case["log"]):
                raise ValueError("fault test did not report exactly one passing test")
            case.update(status="passed", cleanup=scenario.cleanup)
        except subprocess.TimeoutExpired:
            case.update(status="timed_out", error="fault process deadline exceeded")
        except KeyboardInterrupt:
            case.update(status="interrupted", error="operator interrupted qualification")
        except (OSError, ValueError, subprocess.SubprocessError) as error:
            case.update(status="failed", error=str(error))
        case.update(ended_at=timestamp(), elapsed_secs=time.monotonic() - started)
        manifest["status"] = case["status"] if case["status"] != "passed" else "running"
        persist(manifest_path, manifest)
        if case["status"] != "passed":
            break
    else:
        manifest["status"] = "passed"
    manifest["ended_at"] = timestamp()
    persist(manifest_path, manifest)
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--scenario-timeout-secs", type=float, default=600)
    args = parser.parse_args()

    def interrupted(signum, frame):
        raise KeyboardInterrupt

    previous = signal.signal(signal.SIGTERM, interrupted)
    try:
        result = run_faults(Path(__file__).resolve().parents[1], args.output,
                            args.scenario_timeout_secs)
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        print(f"Recovery qualification refused: {error}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        return 130
    finally:
        signal.signal(signal.SIGTERM, previous)
    print(f"Recovery qualification {result['status']}: {args.output.resolve() / 'manifest.json'}")
    return 0 if result["status"] == "passed" else 1


if __name__ == "__main__":
    sys.exit(main())
