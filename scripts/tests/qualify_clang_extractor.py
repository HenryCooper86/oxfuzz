#!/usr/bin/env python3
"""Exercise the real extractor against inert C/C++ fixture source in a container."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


class ClangAnalysisTests(unittest.TestCase):
    def analyze(self, source, extension="c", headers=None, units=None, overrides=None, failure=None):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for name in ("source", "input", "output"):
                (root / name).mkdir()
            (root / "source" / f"unit.{extension}").write_text(source)
            for name, text in (headers or {}).items():
                (root / "source" / name).write_text(text)
            request = {"schema_version": 1, "max_functions": 1000, "max_calls": 1000,
                       "max_output_bytes": 1048576,
                       "units": [{"id": "a" * 64, "file": f"unit.{extension}",
                                  "scope": "a" * 64, "directory": "/work/source",
                                  "arguments": ["-x", "c++" if extension == "cpp" else "c",
                                                "-std=c++17" if extension == "cpp" else "-std=c11"]}]}
            if units is not None:
                request["units"] = units
            request.update(overrides or {})
            (root / "input" / "request.json").write_text(json.dumps(request))
            result = subprocess.run(["docker", "run", "--rm", "--network=none",
                                     "--cap-drop=ALL", "--security-opt=no-new-privileges",
                                     "-v", f"{root}:/work", "--entrypoint",
                                     "/usr/local/bin/oxfuzz-clang-analyze",
                                     os.environ.get("OXFUZZ_CLANG_TEST_IMAGE", "oxfuzz/clang-analysis:test")],
                                    capture_output=True, text=True, timeout=120, check=False)
            if failure is not None:
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(failure, result.stderr)
                self.assertFalse((root / "output" / "index.json").exists())
                return None
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

    def test_project_header_declarations_and_builtin_headers_are_retained(self):
        result = self.analyze('#include <stddef.h>\n#include "api.h"\nint parse(char*x){return *x;}', headers={"api.h": "int parse(char*x);\n"})
        declaration = next(f for f in result["functions"] if f["name"] == "parse")
        self.assertIn("api.h", [location["file"] for location in declaration["declarations"]])

    def test_definition_location_matches_multiline_scanner_start(self):
        result = self.analyze("int\nparse(char*x){return *x;}")
        declaration = next(f for f in result["functions"] if f["name"] == "parse")
        self.assertEqual(declaration["location"]["line"], 1)

    def test_line_directives_keep_physical_definition_and_call_locations(self):
        result = self.analyze('#line 100 "grammar.y"\nvoid leaf(void){}\nint parse(int x){leaf();return x;}')
        declaration = next(f for f in result["functions"] if f["name"] == "parse")
        self.assertTrue(declaration["definition"])
        self.assertEqual(declaration["location"], {"file": "unit.c", "line": 3, "column": 1})
        self.assertEqual(result["calls"][0]["location"]["file"], "unit.c")
        self.assertEqual(result["calls"][0]["location"]["line"], 3)

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

    def test_static_names_and_opposite_macro_variants_remain_unit_scoped(self):
        units = [{"id": name * 64, "scope": name * 64, "file": file,
                  "directory": "/work/source", "arguments": ["-x", "c", f"-DFEATURE={feature}"]}
                 for name, file, feature in [("a", "unit.c", 1), ("b", "unit.c", 0), ("c", "other.c", 0)]]
        result = self.analyze("static void leaf(void){} static void setup(void){\n#if FEATURE\nleaf();\n#endif\n}\nint entry(int x){setup();return x;}",
                              headers={"other.c": "static void setup(void){} int other(int x){setup();return x;}"}, units=units)
        setup = [f for f in result["functions"] if f["name"] == "setup"]
        self.assertEqual(len(setup), 3)
        self.assertEqual(len({f["id"] for f in setup}), 3)
        names = {f["id"]: f["name"] for f in result["functions"]}
        setup_calls = [c for c in result["calls"] if names[c["caller"]] == "setup"]
        self.assertEqual(len(setup_calls), 1)
        self.assertTrue(setup_calls[0]["caller"].startswith("a" * 64))

    def test_recursion_external_leaf_and_private_method_metadata(self):
        result = self.analyze("extern int external(int); int recurse(int n){return n?recurse(n-1):external(n);}"
                              "class Parser {int parse(int x){return recurse(x);}};", "cpp")
        external = next(f for f in result["functions"] if f["name"] == "external")
        self.assertFalse(external["definition"])
        method = next(f for f in result["functions"] if f["name"] == "Parser::parse")
        self.assertEqual(method["access"], "private")
        self.assertEqual(method["method_kind"], "instance")
        self.assertTrue(any(c["caller"] == c["callee"] for c in result["calls"]))

    def test_parse_protocol_and_collection_failures_publish_no_result(self):
        for overrides, source, error in [
            ({"schema_version": 2}, "int a;", "unsupported schema"),
            ({"max_functions": 1}, "void a(void){} void b(void){}", "function limit"),
            ({"max_calls": 1}, "void a(void){} void b(void){a();a();}", "call limit"),
            ({"max_output_bytes": 1}, "void a(void){}", "output limit"),
            ({}, '#include "absent.h"', "translation unit parse failed"),
        ]:
            with self.subTest(error=error):
                self.analyze(source, overrides=overrides, failure=error)


if __name__ == "__main__":
    unittest.main()
