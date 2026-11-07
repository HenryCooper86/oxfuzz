"""Behavior of scripts/ci/runner-cache-gc.sh against stub docker and df."""

import os
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "ci" / "runner-cache-gc.sh"

RUNNER = "runner-0de51ce8f1353e1f1492a17acb6e2aa0-cache-3c3f060a0374fc8bc39395164f415a70"
PROTECTED = "runner-e624c3da9c15c70cc8f8bd570d3ba6e4-cache-c33bcaa1fd2c77edfc3893b41966cea8-protected"
OTHER = "oxfuzz-ci-target"
LOOKALIKE = "runner-abc-cache-def"


def write_stub(directory: Path, name: str, body: str) -> None:
    path = directory / name
    path.write_text("#!/bin/sh\n" + body)
    path.chmod(path.stat().st_mode | stat.S_IXUSR)


class RunnerCacheGcTest(unittest.TestCase):
    def run_gc(self, usage: int, idle: list[str], rm_status: int = 0):
        with tempfile.TemporaryDirectory() as tmp:
            bin_dir = Path(tmp)
            log = bin_dir / "docker.log"
            listing = "\\n".join(idle)
            write_stub(bin_dir, "df", f"printf 'Use%%\\n {usage}%%\\n'\n")
            write_stub(
                bin_dir,
                "docker",
                f'echo "$@" >> "{log}"\n'
                'if [ "$1 $2" = "volume ls" ]; then\n'
                f"  printf '{listing}\\n'\n"
                "  exit 0\n"
                "fi\n"
                f"exit {rm_status}\n",
            )
            env = dict(os.environ, PATH=f"{bin_dir}:{os.environ['PATH']}")
            result = subprocess.run(
                ["sh", str(SCRIPT)], env=env, capture_output=True, text=True, check=False
            )
            calls = log.read_text().splitlines() if log.exists() else []
            return result, [c for c in calls if c.startswith("volume rm")]

    def test_below_the_threshold_nothing_is_removed(self):
        result, removed = self.run_gc(usage=40, idle=[RUNNER])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(removed, [])
        self.assertIn("nothing to do", result.stdout)

    def test_above_the_threshold_only_runner_cache_volumes_are_removed(self):
        result, removed = self.run_gc(usage=90, idle=[RUNNER, PROTECTED, OTHER, LOOKALIKE])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(removed, [f"volume rm {RUNNER}", f"volume rm {PROTECTED}"])

    def test_no_idle_runner_volume_is_not_an_error(self):
        result, removed = self.run_gc(usage=90, idle=[OTHER])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(removed, [])

    def test_a_failed_removal_fails_the_run(self):
        result, _ = self.run_gc(usage=90, idle=[RUNNER], rm_status=1)
        self.assertNotEqual(result.returncode, 0)

    def test_the_idle_filter_is_requested_from_docker(self):
        # Only volumes no container references are candidates, so a running
        # job keeps its build directory.
        with tempfile.TemporaryDirectory() as tmp:
            bin_dir = Path(tmp)
            log = bin_dir / "docker.log"
            write_stub(bin_dir, "df", "printf 'Use%%\\n 90%%\\n'\n")
            write_stub(bin_dir, "docker", f'echo "$@" >> "{log}"\n')
            env = dict(os.environ, PATH=f"{bin_dir}:{os.environ['PATH']}")
            subprocess.run(["sh", str(SCRIPT)], env=env, capture_output=True, check=False)
            self.assertIn("volume ls -q --filter dangling=true", log.read_text())


if __name__ == "__main__":
    unittest.main()
