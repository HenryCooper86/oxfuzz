"""Validate an admitted cross-platform diagnostic bundle without timing gates."""

import argparse
import hashlib
import json
from pathlib import Path
import re
import sys
from urllib.parse import urlsplit

from scripts import check_dispatch_samples, check_history_samples


def positive_bytes(value):
    number = int(value)
    if number < 1:
        raise argparse.ArgumentTypeError("report byte allowance must be positive")
    return number


def load_report(path, max_bytes):
    """Read at most the resolved allowance plus one byte before decoding."""
    with path.open("rb") as source:
        raw = source.read(max_bytes + 1)
    if len(raw) > max_bytes:
        raise ValueError("report exceeds byte allowance")
    return json.loads(raw), "sha256:" + hashlib.sha256(raw).hexdigest()


def require_record(record, text_fields, integer_fields):
    if not isinstance(record, dict) or type(record.get("schema_version")) is not int or record["schema_version"] != 1:
        raise ValueError("diagnostic identity schema is invalid")
    if any(not isinstance(record.get(field), str) or not record[field].strip() for field in text_fields):
        raise ValueError("diagnostic identity is incomplete")
    if any(type(record.get(field)) is not int or record[field] < 1 for field in integer_fields):
        raise ValueError("diagnostic run identity is invalid")


def summarize(dispatch, history, receipt, actual_runner, *, revision, runner):
    """Reuse sample checks, then bind their identities to this workflow admission."""
    if not re.fullmatch(r"[0-9a-f]{40}", revision) or not runner.strip():
        raise ValueError("expected diagnostic identity is invalid")
    require_record(receipt, ("candidate_commit", "ci_url"), ("ci_run_id", "ci_run_attempt"))
    url = urlsplit(receipt["ci_url"])
    if url.scheme != "https" or not url.hostname or url.username or url.password:
        raise ValueError("source CI URL must use HTTPS without credentials")
    runner_text = ("candidate_commit", "runner", "runner_os", "runner_arch", "runner_name",
                   "image_os", "image_version")
    runner_integers = ("workflow_run_id", "workflow_run_attempt")
    require_record(actual_runner, runner_text, runner_integers)
    if receipt["candidate_commit"] != revision or actual_runner["candidate_commit"] != revision or actual_runner["runner"] != runner:
        raise ValueError("diagnostic admission or runner identifies a different candidate")
    dispatch_rows = check_dispatch_samples.summarize(dispatch)
    history_rows = check_history_samples.summarize(history)
    shared_fields = ("revision", "runner", "rustc", "os", "arch", "profile", "clean")
    environment = {field: dispatch["environment"][field] for field in shared_fields}
    if any(history["environment"][field] != environment[field] for field in shared_fields):
        raise ValueError("diagnostic reports name different measured environments")
    if environment["revision"] != revision or environment["runner"] != runner or environment["profile"] != "release":
        raise ValueError("diagnostic reports require the admitted release profile and runner")
    if dispatch["environment"]["fixture"] != "noop-schema-v1" or dispatch["environment"]["runtime_workers"] != 4:
        raise ValueError("diagnostic dispatch fixture is not the selected measurement")
    systems = {"Linux": "linux", "Windows": "windows", "macOS": "macos"}
    architectures = {"X64": "x86_64", "ARM64": "aarch64"}
    if environment["os"] != systems.get(actual_runner["runner_os"]) or environment["arch"] != architectures.get(actual_runner["runner_arch"]):
        raise ValueError("reported OS or architecture differs from the actual runner")
    return {
        "schema_version": 1, "scope": "shared-runner-diagnostic", "environment": environment,
        "source_ci": {field: receipt[field] for field in
                      ("schema_version", "candidate_commit", "ci_run_id", "ci_run_attempt", "ci_url")},
        "runner": {field: actual_runner[field] for field in ("schema_version", *runner_text, *runner_integers)},
        "dispatch": dispatch_rows, "history": history_rows,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", required=True, type=Path)
    parser.add_argument("--revision", required=True)
    parser.add_argument("--runner", required=True)
    parser.add_argument("--max-report-bytes", type=positive_bytes, default=1024 * 1024)
    args = parser.parse_args()
    output = args.directory / "summary.json"
    try:
        # A failed recheck must not leave a previous accepted summary in the bundle.
        output.unlink(missing_ok=True)
        names = ("dispatch", "history", "source-ci", "runner")
        inputs = [load_report(args.directory / f"{name}.json", args.max_report_bytes) for name in names]
        result = summarize(*(document for document, _ in inputs), revision=args.revision, runner=args.runner)
        result["digests"] = {name: digest for name, (_, digest) in zip(names, inputs)}
        output.write_text(json.dumps(result, indent=2, allow_nan=False) + "\n", encoding="utf-8")
    except (OSError, ValueError, TypeError, KeyError) as error:
        print(f"Performance diagnostics invalid: {error}", file=sys.stderr)
        return 1
    print(f"Validated diagnostic bundle for {args.revision} on {args.runner}; no timing threshold enforced.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
