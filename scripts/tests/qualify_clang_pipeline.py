#!/usr/bin/env python3
"""Qualify Clang sandbox publication and persisted provider input using inert fixtures.

Requires the CLI built with clang-analysis and a qualification image containing
LLVM 18 and oxfuzz-clang-analyze. No generated harness is built or executed.
"""
import argparse
import http.server
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import tempfile
import threading


def qualify(cli, image):
    requests = []

    class Provider(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            request = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            requests.append(request)
            response = {"id": "fixture", "object": "chat.completion", "created": 0,
                        "model": "fixture", "choices": [{"index": 0, "finish_reason": "stop",
                        "message": {"role": "assistant", "content": "```c\nint LLVMFuzzerTestOneInput(const unsigned char*d,unsigned long n){return 0;}\n```"}}],
                        "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2}}
            body = json.dumps(response).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_args):
            pass

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Provider)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        with tempfile.TemporaryDirectory(prefix="oxfuzz-clang-qualification-") as directory:
            root = Path(directory)
            project = root / "project"
            project.mkdir()
            (project / "model.h").write_text("/* required project header */\n")
            source = project / "parser.c"
            source.write_text("#ifdef __cplusplus\nint cpp_leaf(const char *data){return data[0];}\n#define LEAF cpp_leaf\n"
                              "#else\nint c_leaf(const char *data){return data[0];}\n#define LEAF c_leaf\n#endif\n"
                              "int parse(const char *data,unsigned size){if(size)return LEAF(data);return 0;}\n")
            (project / "compile_commands.json").write_text(json.dumps([{
                "directory": str(project), "file": "parser.c",
                "arguments": ["clang++", "-std=c++17", "-include", "model.h", "-c", "parser.c", "-o", "parser.o"]}]))
            config = root / "config"
            config.mkdir()
            (config / "oxfuzz.toml").write_text(f"[clang_analysis]\nimage = {json.dumps(image)}\n")
            env = os.environ.copy()
            env.update(HF_CONFIG_DIR=str(config), HF_DB_PATH=str(root / "state.db"),
                       HF_WORKSPACE_DIR=str(root / "workspace"), HF_USE_DOCKER="1",
                       HF_AUTO_APPROVE="1", HF_PROVIDER_API_KEY="fixture-key",
                       HF_PROVIDER_MODEL="fixture", HF_PROVIDER_BASE_URL=f"http://127.0.0.1:{server.server_port}/v1")

            def run(*args, expect_failure=False):
                completed = subprocess.run([str(cli), *args], env=env, capture_output=True,
                                           text=True, timeout=180, check=False)
                if expect_failure:
                    assert completed.returncode != 0, "provider dispatch should have been refused"
                elif completed.returncode:
                    raise AssertionError(completed.stderr)
                return completed.stdout

            result = json.loads(run("discover", str(project), "--lang", "c", "--clang"))
            assert result["analysis"]["image_id"].startswith("sha256:")
            assert any(f["name"] == "parse" for f in result["analysis"]["index"]["functions"])
            names = {f["name"] for f in result["analysis"]["index"]["functions"]}
            assert "cpp_leaf" in names and "c_leaf" not in names, "C++ driver language was lost for .c source"
            run("harness", str(project), "--target", "parse", "--engine", "libfuzzer", "--lang", "c", "--draft-only", "--ai", "require")
            run("harness", str(project), "--target", "parse", "--engine", "afl++", "--persistent", "--lang", "c", "--draft-only", "--ai", "require")
            database = sqlite3.connect(root / "state.db")
            sections = database.execute("SELECT rendered FROM harness_clang_contexts ORDER BY created_at, id").fetchall()
            assert len(sections) == 2, "ordinary/persistent drafts did not both retain analysis"
            assert len(requests) == 2, "each draft should dispatch exactly once"
            for section, request in zip(sections, requests):
                assert any(section[0] in message["content"] for message in request["messages"]), "provider request differs from durable section"
            assert '"name":"parse"' in sections[-1][0]
            assert "potential static call" in sections[-1][0]
            before = len(sections)
            provider_calls = len(requests)
            database.execute("CREATE TRIGGER refuse_context BEFORE INSERT ON harness_clang_contexts BEGIN SELECT RAISE(ABORT, 'fixture persistence failure'); END")
            database.commit()
            run("harness", str(project), "--target", "parse", "--engine", "libfuzzer", "--lang", "c", "--draft-only", "--ai", "require", expect_failure=True)
            assert len(requests) == provider_calls, "provider called before durable context write"
            database.execute("DROP TRIGGER refuse_context")
            database.commit()
            source.write_text(source.read_text() + "/* changed source */\n")
            run("harness", str(project), "--target", "parse", "--engine", "libfuzzer", "--lang", "c", "--draft-only", "--ai", "require")
            assert database.execute("SELECT count(*) FROM harness_clang_contexts").fetchone()[0] == before
            assert all("<clang_analysis_data>" not in m["content"] for m in requests[-1]["messages"])
            (project / "model.h").unlink()
            run("harness", str(project), "--target", "parse", "--engine", "libfuzzer", "--lang", "c", "--draft-only", "--ai", "require")
            assert database.execute("SELECT count(*) FROM harness_clang_contexts").fetchone()[0] == before
            database.close()
            print("Clang sandbox publication, persisted provider context, and stale-source exclusion passed")
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--cli", required=True, type=Path)
    parser.add_argument("--image", default="oxfuzz/clang-analysis:test")
    arguments = parser.parse_args()
    qualify(arguments.cli.resolve(), arguments.image)
