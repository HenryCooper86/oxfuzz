#!/usr/bin/env python3
"""Run explicitly approved sandbox qualification cycles and retain their outcomes."""
import argparse
import hashlib
import json
import math
import os
import platform
from pathlib import Path
import signal
import statistics
import subprocess
import sys
import time
import uuid
from datetime import datetime, timezone

ENGINES = ("libfuzzer", "afl++", "honggfuzz")
COMMAND = ["cargo", "test", "-p", "hf-service", "--features", "proof-carrying",
           "--test", "cancellation_live", "stop_button_cancels_a_real_fuzz_run",
           "--", "--ignored", "--exact", "--nocapture"]


def source_digest(repo):
    """Match the live test's identity over both approved source files."""
    sources = repo / "examples/qualification"
    return hashlib.sha256((sources / "parser.c").read_bytes() + b"\0" +
                          (sources / "harness.c").read_bytes()).hexdigest()


def revision_identity(repo):
    """Record source identities without retaining environment values or diff text."""
    def git(*args):
        return subprocess.check_output(["git", *args], cwd=repo, timeout=30)
    files = git("ls-files", "-z", "--cached", "--others", "--exclude-standard")
    hashes = {}
    for raw in sorted(set(files.split(b"\0")) - {b""}):
        name = os.fsdecode(raw)
        path = repo / name
        if path.is_symlink():
            hashes[name] = {"symlink": os.readlink(path)}
        elif path.is_file():
            digest = hashlib.sha256()
            with path.open("rb") as stream:
                for block in iter(lambda: stream.read(1024 * 1024), b""):
                    digest.update(block)
            hashes[name] = {"sha256": digest.hexdigest(), "mode": path.stat().st_mode & 0o777}
        else:
            hashes[name] = {"missing": True}
    return {"commit": git("rev-parse", "HEAD").decode().strip(),
            "patch_sha256": hashlib.sha256(git("diff", "HEAD", "--binary")).hexdigest(),
            "files": hashes}


def persist(path, value):
    """Replace a manifest only after its complete contents reach durable storage."""
    temporary = path.with_suffix(".tmp")
    with temporary.open("w", encoding="utf-8") as stream:
        json.dump(value, stream, indent=2, allow_nan=False)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    temporary.replace(path)
    descriptor = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def run_process(command, repo, env, log, timeout):
    """Supervise only this child group; sandbox cleanup remains a separate outcome."""
    with log.open("wb") as stream:
        process = subprocess.Popen(command, cwd=repo, env=env, stdout=stream,
                                   stderr=subprocess.STDOUT, start_new_session=True)
        try:
            return process.wait(timeout=timeout)
        except BaseException:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                # The owned process group already exited; wait still reaps its leader.
                pass
            process.wait()
            raise


def read_reports(root):
    """Require one complete fixture report per engine, with no reused campaign ids."""
    reports = {}
    ids = set()
    paths = list(root.glob("qualification-*/*/qualification.json"))
    if len(paths) != len(ENGINES):
        raise ValueError("qualification evidence must contain exactly three engine reports")
    for path in paths:
        if path.is_symlink() or not path.is_file() or path.stat().st_size > 1024 * 1024:
            raise ValueError("qualification evidence is not a bounded regular report")
        record = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(record, dict):
            raise ValueError("qualification evidence must be a JSON object")
        engine = record.get("engine")
        if engine not in ENGINES or engine in reports or path.parent.name != engine:
            raise ValueError("qualification evidence has an unknown or duplicate engine")
        for name in ("campaign_run_id", "replay_run_id"):
            if not isinstance(record.get(name), str):
                raise ValueError("qualification evidence is missing a run UUID")
            value = str(uuid.UUID(record[name]))
            if value in ids:
                raise ValueError("qualification evidence reuses a run id")
            ids.add(value)
            record[name] = value
        if not isinstance(record.get("harness_id"), str):
            raise ValueError("qualification evidence is missing a harness UUID")
        uuid.UUID(record["harness_id"])
        stop = record.get("stop_ms")
        if type(stop) is not int or not 0 <= stop <= 15000:
            raise ValueError("qualification evidence has an invalid Stop latency")
        smoke = record.get("smoke")
        verdict = smoke.get("verdict") if isinstance(smoke, dict) else None
        if not isinstance(verdict, dict) or verdict.get("level") != "pass":
            raise ValueError("qualification evidence does not contain a passing smoke")
        reports[engine] = {"report": str(path.relative_to(root)), "stop_ms": stop,
                           "campaign_run_id": record["campaign_run_id"],
                           "replay_run_id": record["replay_run_id"]}
    return reports


def timestamp():
    return datetime.now(timezone.utc).isoformat()


def run_qualification(repo, output, cycles, timeout, approval, *, executor=run_process):
    """Stop at the first incomplete cycle; never reuse or overwrite earlier evidence."""
    if os.name != "posix":
        raise ValueError("qualification process supervision currently requires POSIX")
    if type(cycles) is not int or not 1 <= cycles <= 10000:
        raise ValueError("cycles must be an integer from 1 through 10000")
    if not math.isfinite(timeout) or not 0 < timeout <= 86400:
        raise ValueError("cycle timeout must be positive and at most 86400 seconds")
    repo, output = repo.resolve(), output.resolve()
    if output == repo or repo in output.parents:
        raise ValueError("qualification evidence must be outside the measured repository")
    digest = source_digest(repo)
    if approval != digest:
        raise ValueError("source approval must match both exact qualification sources")
    identity = revision_identity(repo)
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    manifest_path = output / "manifest.json"
    manifest = {"version": 1, "status": "running", "started_at": timestamp(),
                "source_sha256": digest, "revision": identity, "command": COMMAND,
                "platform": platform.platform(), "python": platform.python_version(),
                "requested_cycles": cycles, "cycle_timeout_secs": timeout, "cycles": []}
    persist(manifest_path, manifest)
    retained_ids = set()
    for index in range(cycles):
        cycle_root = output / f"cycle-{index + 1:05}"
        cycle_root.mkdir(mode=0o700)
        cycle = {"index": index + 1, "status": "running", "started_at": timestamp(),
                 "evidence": cycle_root.name, "cleanup": "unverified"}
        manifest["cycles"].append(cycle)
        persist(manifest_path, manifest)
        started = time.monotonic()
        try:
            if source_digest(repo) != digest or revision_identity(repo) != identity:
                raise ValueError("approved source or repository changed between cycles")
            env = dict(os.environ, OXFUZZ_LIVE_APPROVAL_SHA256=approval,
                       OXFUZZ_LIVE_EVIDENCE_ROOT=str(cycle_root))
            code = executor(COMMAND, repo, env, cycle_root / "process.log", timeout)
            cycle["exit_code"] = code
            if code != 0:
                raise ValueError(f"qualification process exited with status {code}")
            if source_digest(repo) != digest or revision_identity(repo) != identity:
                raise ValueError("approved source or repository changed during qualification")
            reports = read_reports(cycle_root)
            cycle_ids = {report[name] for report in reports.values()
                         for name in ("campaign_run_id", "replay_run_id")}
            if retained_ids.intersection(cycle_ids):
                raise ValueError("qualification evidence reuses a run from an earlier cycle")
            retained_ids.update(cycle_ids)
            cycle["reports"] = reports
            cycle.update(status="passed", cleanup="verified_by_fixture")
        except subprocess.TimeoutExpired:
            cycle.update(status="timed_out", error="cycle process deadline exceeded")
        except KeyboardInterrupt:
            cycle.update(status="interrupted", error="operator interrupted qualification")
        except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
            cycle.update(status="failed", error=str(error))
        cycle.update(ended_at=timestamp(), elapsed_secs=time.monotonic() - started)
        manifest["status"] = cycle["status"] if cycle["status"] != "passed" else "running"
        persist(manifest_path, manifest)
        if cycle["status"] != "passed":
            break
    else:
        manifest["status"] = "passed"
        manifest["stop_latency_ms"] = {}
        for engine in ENGINES:
            values = sorted(cycle["reports"][engine]["stop_ms"] for cycle in manifest["cycles"])
            manifest["stop_latency_ms"][engine] = {"samples": len(values),
                "median": statistics.median(values), "p95": values[math.ceil(len(values) * 0.95) - 1]}
    manifest["ended_at"] = timestamp()
    persist(manifest_path, manifest)
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path, help="new durable evidence directory")
    parser.add_argument("--cycles", required=True, type=int)
    parser.add_argument("--cycle-timeout-secs", required=True, type=float)
    args = parser.parse_args()
    def interrupted(signum, frame):
        raise KeyboardInterrupt
    previous = signal.signal(signal.SIGTERM, interrupted)
    try:
        result = run_qualification(Path(__file__).resolve().parents[1], args.output.resolve(),
            args.cycles, args.cycle_timeout_secs, os.environ.get("OXFUZZ_LIVE_APPROVAL_SHA256", ""))
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        print(f"Qualification refused: {error}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        return 130
    finally:
        signal.signal(signal.SIGTERM, previous)
    print(f"Qualification {result['status']}: {args.output.resolve() / 'manifest.json'}")
    return 0 if result["status"] == "passed" else 1


if __name__ == "__main__":
    sys.exit(main())
