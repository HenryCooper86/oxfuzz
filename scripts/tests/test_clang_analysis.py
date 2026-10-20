#!/usr/bin/env python3
"""Exercise the real extractor against inert C/C++ fixture source in a container."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


class ClangAnalysisTests(unittest.TestCase):
    def analyze(self, source, extension="c"):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for name in ("source", "input", "output"):
                (root / name).mkdir()
            (root / "source" / f"unit.{extension}").write_text(source)
            request = {"schema_version": 1, "max_functions": 1000, "max_calls": 1000,
                       "max_output_bytes": 1048576,
                       "units": [{"id": "a" * 64, "file": f"unit.{extension}",
                                  "scope": "a" * 64, "directory": "/work/source",
                                  "arguments": ["-x", "c++" if extension == "cpp" else "c",
                                                "-std=c++17" if extension == "cpp" else "-std=c11"]}]}
            (root / "input" / "request.json").write_text(json.dumps(request))
            result = subprocess.run(["docker", "run", "--rm", "--network=none",
                                     "--cap-drop=ALL", "--security-opt=no-new-privileges",
                                     "-v", f"{root}:/work", "--entrypoint",
                                     "/usr/local/bin/oxfuzz-clang-analyze",
                                     os.environ.get("OXFUZZ_CLANG_TEST_IMAGE", "oxfuzz/clang-analysis:test")],
                                    capture_output=True, text=True, timeout=120, check=False)
            self.assertEqual(result.returncode, 0, result.stderr)
            return json.loads((root / "output" / "index.json").read_text())

    def test_zero_argument_helper_and_indirect_call(self):
        result = self.analyze("void leaf(void){} void setup(void){leaf();} "
                              "int entry(void(*callback)(void)){setup(); callback(); return 0;}")
        names = {f["id"]: f["name"] for f in result["functions"]}
        edges = {(names[c["caller"]], names.get(c["callee"]), c["dispatch"])
                 for c in result["calls"]}
        self.assertIn(("entry", "setup", "direct"), edges)
        self.assertIn(("setup", "leaf", "direct"), edges)
        self.assertIn(("entry", None, "indirect"), edges)
        self.assertEqual(result["schema_version"], 1)
        self.assertEqual(len(result["helper_sha256"]), 64)

    def test_method_bodies_keep_their_own_caller(self):
        result = self.analyze("void leaf(){} struct Parser {int parse(int x){leaf();return x;}};", "cpp")
        names = {f["id"]: f["name"] for f in result["functions"]}
        self.assertTrue(any(names[c["caller"]] == "Parser::parse" and
                            names.get(c["callee"]) == "leaf" for c in result["calls"]))

    def test_overloads_and_virtual_dispatch(self):
        result = self.analyze("namespace n {int parse(int x){return x;} int parse(char*x){return *x;}} "
                              "struct Base {virtual int decode(int)=0;}; "
                              "int entry(Base*b,int x){return b->decode(n::parse(x));}", "cpp")
        overloads = [f for f in result["functions"] if f["name"] == "n::parse"]
        self.assertEqual(len(overloads), 2)
        self.assertNotEqual(overloads[0]["id"], overloads[1]["id"])
        self.assertTrue(any(c["dispatch"] == "virtual" for c in result["calls"]))


if __name__ == "__main__":
    unittest.main()
