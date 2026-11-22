#!/usr/bin/env python3
"""The sandbox build script hands a container engine Windows paths from Git Bash.

Git Bash reports host paths as `/d/a/...`, which no container engine accepts
as a bind source, and rewrites arguments that look like POSIX paths, which
corrupts paths meant for the container. The script must convert the first
kind itself and switch the rewriting off. A stand-in `cygpath` makes the
conversion visible on any host.
"""

import json
import os
import pathlib
import subprocess
import tempfile
import unittest


REPOSITORY_ROOT = pathlib.Path(__file__).resolve().parents[2]
CLEAN_REPORT = {
    "version": "1.169.0",
    "results": [{"check_id": "raptor-insecure-api-gets", "path": "vulnerable.c"}],
    "errors": [],
    "paths": {"scanned": ["clean.c", "vulnerable.c"]},
}

FAKE_CYGPATH = """#!/usr/bin/env python3
import sys
assert sys.argv[1] == '-w', sys.argv
print('W:' + sys.argv[2])
"""

FAKE_DOCKER = """#!/usr/bin/env python3
import json, os, pathlib, sys
log = pathlib.Path(os.environ['OXFUZZ_FIXTURE_LOG'])
with log.open('a', encoding='utf-8') as handle:
    handle.write(json.dumps({'argv': sys.argv[1:],
                             'no_pathconv': os.environ.get('MSYS_NO_PATHCONV'),
                             'conv_excl': os.environ.get('MSYS2_ARG_CONV_EXCL')}) + '\\n')
for argument in sys.argv:
    if argument.startswith('type=bind,src=W:') and argument.endswith(',dst=/work/output'):
        output = pathlib.Path(argument.removeprefix('type=bind,src=W:').removesuffix(',dst=/work/output'))
        (output / 'semgrep.json').write_text(os.environ['OXFUZZ_FIXTURE_REPORT'])
if sys.argv[1:3] == ['image', 'inspect']:
    print('Verified sha256:fixture (amd64)')
"""


class SandboxBuildFromGitBashTests(unittest.TestCase):
    def run_build(self, with_cygpath: bool) -> tuple[subprocess.CompletedProcess[str], list[dict]]:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            tools = root / "tools"
            tools.mkdir()
            (tools / "docker").write_text(FAKE_DOCKER, encoding="utf-8")
            (tools / "docker").chmod(0o700)
            if with_cygpath:
                (tools / "cygpath").write_text(FAKE_CYGPATH, encoding="utf-8")
                (tools / "cygpath").chmod(0o700)
            log = root / "docker.log"
            log.touch()
            environment = dict(os.environ)
            environment.update({
                "PATH": f"{tools}{os.pathsep}{environment['PATH']}",
                "OXFUZZ_FIXTURE_REPORT": json.dumps(CLEAN_REPORT),
                "OXFUZZ_FIXTURE_LOG": str(log),
            })
            environment.pop("MSYS_NO_PATHCONV", None)
            environment.pop("MSYS2_ARG_CONV_EXCL", None)
            result = subprocess.run(
                ["bash", str(REPOSITORY_ROOT / "scripts/build-sandbox.sh")],
                env=environment, capture_output=True, text=True, timeout=30, check=False)
            calls = [json.loads(line) for line in log.read_text(encoding="utf-8").splitlines()]
            return result, calls

    @staticmethod
    def bind_sources(calls: list[dict]) -> list[str]:
        return [argument.removeprefix("type=bind,src=").split(",dst=")[0]
                for call in calls for argument in call["argv"]
                if argument.startswith("type=bind,src=")]

    def test_bind_sources_are_converted_and_argument_rewriting_is_off(self) -> None:
        result, calls = self.run_build(with_cygpath=True)
        sources = self.bind_sources(calls)
        self.assertEqual(len(sources), 2, result.stderr)
        for source in sources:
            self.assertTrue(source.startswith("W:/"), source)
        self.assertTrue(sources[0].endswith("/docker/sandbox/semgrep/fixtures"), sources[0])
        self.assertTrue(all(call["no_pathconv"] == "1" for call in calls), calls)
        self.assertTrue(all(call["conv_excl"] == "*" for call in calls), calls)

    def test_without_cygpath_the_paths_are_passed_as_they_are(self) -> None:
        result, calls = self.run_build(with_cygpath=False)
        sources = self.bind_sources(calls)
        self.assertEqual(len(sources), 2, result.stderr)
        for source in sources:
            self.assertTrue(source.startswith("/"), source)


if __name__ == "__main__":
    unittest.main()
