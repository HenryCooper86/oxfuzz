#!/usr/bin/env bash
# Verify the pinned Semgrep integration without executing Semgrep on the host.
set -euo pipefail

repository_root="$(cd "$(dirname "$0")/.." && pwd -P)"
git_repository_root="$(git -C "$repository_root" rev-parse --show-toplevel)"
git_repository_root="$(cd "$git_repository_root" && pwd -P)"
if [[ "$repository_root" != "$git_repository_root" ]]; then
    echo "repository root mismatch: ${repository_root}" >&2
    exit 1
fi
cd "$repository_root"

readonly REPOSITORY_ROOT="$repository_root"
readonly IMAGE="${OXFUZZ_SANDBOX_IMAGE:-oxfuzz/fuzz-sandbox:0.1.0}"
readonly SEMGREP_VERSION="1.169.0"
readonly RULES_COMMIT="4d66ecf30bfb1809a984085f2c86a8c3915bfc71"
readonly RULES_TREE_SHA256="b7b7a88a780c5f7cfe8ce7afc05af84165419e35aa0b1ef7fb553f58667fa613"
readonly OUTPUT_LIMIT_BYTES=67108864

if [[ "$IMAGE" == "latest" || "$IMAGE" == *":latest" ]]; then
    echo "OXFUZZ_SANDBOX_IMAGE must use an explicit version tag" >&2
    exit 1
fi
if [[ ! "$IMAGE" =~ ^[[:alnum:]][[:alnum:]_.:/@-]*$ ]]; then
    echo "OXFUZZ_SANDBOX_IMAGE is not a versioned image reference" >&2
    exit 1
fi
if [[ "$IMAGE" == *@* ]]; then
    if [[ ! "$IMAGE" =~ @sha256:[[:xdigit:]]{64}$ ]]; then
        echo "OXFUZZ_SANDBOX_IMAGE is not a pinned SHA-256 image reference" >&2
        exit 1
    fi
else
    image_name="${IMAGE##*/}"
    if [[ "$image_name" != *:* || -z "${image_name##*:}" ]]; then
        echo "OXFUZZ_SANDBOX_IMAGE is not a versioned image reference" >&2
        exit 1
    fi
fi
if ! resolved_image="$(docker image inspect --format '{{.Id}}' "$IMAGE" 2>/dev/null)"; then
    echo "pinned sandbox image is not available locally: ${IMAGE}" >&2
    echo "build it explicitly with ./scripts/build-sandbox.sh before running this gate" >&2
    exit 1
fi
if [[ ! "$resolved_image" =~ ^sha256:[[:xdigit:]]{64}$ ]]; then
    echo "sandbox image did not resolve to an immutable image id: ${resolved_image}" >&2
    exit 1
fi
readonly RESOLVED_IMAGE="$resolved_image"

for release_file in \
    third_party/semgrep/LICENSE \
    third_party/semgrep-rules/LICENSE \
    docker/sandbox/semgrep/fixtures/vulnerable.c \
    docker/sandbox/semgrep/fixtures/clean.c; do
    if [[ ! -f "$release_file" || -L "$release_file" || ! -s "$release_file" ]]; then
        echo "required release input is not a regular non-empty file: ${release_file}" >&2
        exit 1
    fi
    git ls-files --error-unmatch "$release_file" >/dev/null
done

temp_base="${TMPDIR:-/tmp}"
temp_base="$(cd "$temp_base" && pwd -P)"
if [[ "$temp_base" != /* || "$temp_base" == "/" ||
      "$temp_base" == *$'\n'* || "$temp_base" == *","* ]]; then
    echo "refusing unsafe temporary directory base: ${temp_base}" >&2
    exit 1
fi

verification_root=""
candidate_root="$(mktemp -d "${temp_base%/}/oxfuzz-semgrep-smoke.XXXXXXXX")"
if [[ ! -d "$candidate_root" || -L "$candidate_root" ||
      "$candidate_root" != "${temp_base%/}/oxfuzz-semgrep-smoke."* ||
      "$(cd "$candidate_root" && pwd -P)" != "$candidate_root" ]]; then
    echo "refusing unvalidated verification directory: ${candidate_root}" >&2
    exit 1
fi
verification_root="$candidate_root"

cleanup() {
    local resolved_root
    if [[ -z "$verification_root" || ! -d "$verification_root" ||
          -L "$verification_root" ||
          "$verification_root" != "${temp_base%/}/oxfuzz-semgrep-smoke."* ]]; then
        echo "refusing to remove unvalidated verification directory: ${verification_root}" >&2
        return 1
    fi
    resolved_root="$(cd "$verification_root" && pwd -P)"
    if [[ "$resolved_root" != "$verification_root" ]]; then
        echo "refusing to remove replaced verification directory: ${verification_root}" >&2
        return 1
    fi
    rm -rf -- "$verification_root"
}
trap cleanup EXIT

source_root="${verification_root}/source"
output_root="${verification_root}/output"
mkdir "$source_root" "$output_root"
cp docker/sandbox/semgrep/fixtures/vulnerable.c "$source_root/vulnerable.c"
cp docker/sandbox/semgrep/fixtures/clean.c "$source_root/clean.c"

docker_hardening=(
    --rm
    --network none
    --read-only
    --cap-drop ALL
    --security-opt no-new-privileges
    --pids-limit 128
    --memory 4096m
    --cpus 2
    --ulimit "fsize=${OUTPUT_LIMIT_BYTES}:${OUTPUT_LIMIT_BYTES}"
    --tmpfs /tmp:rw,nosuid,nodev,size=64m
)

echo "Verifying Semgrep provenance in ${IMAGE} ..."
docker run "${docker_hardening[@]}" \
    --entrypoint /bin/sh \
    "$RESOLVED_IMAGE" -eu -c '
        test "$(semgrep --version --disable-version-check)" = "1.169.0"
        test "$(cat /opt/oxfuzz/semgrep-rules/COMMIT)" = \
            "4d66ecf30bfb1809a984085f2c86a8c3915bfc71"
        test "$(cat /opt/oxfuzz/semgrep-rules/RULES_SHA256)" = \
            "b7b7a88a780c5f7cfe8ce7afc05af84165419e35aa0b1ef7fb553f58667fa613"
        test "$(
            python3 /opt/oxfuzz/semgrep-tree-digest.py \
                /opt/oxfuzz/semgrep-rules/rules/c
        )" = "b7b7a88a780c5f7cfe8ce7afc05af84165419e35aa0b1ef7fb553f58667fa613"
    '

echo "Running the fixed Semgrep fixture scan ..."
docker run "${docker_hardening[@]}" \
    --mount "type=bind,src=${source_root},dst=/work/source,readonly" \
    --mount "type=bind,src=${output_root},dst=/work/output" \
    "$RESOLVED_IMAGE" /usr/local/bin/oxfuzz-semgrep-scan

python3 - "$output_root/semgrep.json" "$OUTPUT_LIMIT_BYTES" <<'PY'
import json
import os
import pathlib
import stat
import sys

report_path = pathlib.Path(sys.argv[1])
limit = int(sys.argv[2])
report_fd = os.open(
    report_path,
    os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
)
report_stat = os.fstat(report_fd)
if not stat.S_ISREG(report_stat.st_mode):
    os.close(report_fd)
    raise SystemExit("Semgrep report is not a regular file")
if report_stat.st_size > limit:
    os.close(report_fd)
    raise SystemExit(f"Semgrep report exceeds {limit} bytes")
with os.fdopen(report_fd, "rb") as report_file:
    report_bytes = report_file.read(limit + 1)
if not report_bytes:
    raise SystemExit("Semgrep report is empty")
if len(report_bytes) > limit:
    raise SystemExit(f"Semgrep report exceeds {limit} bytes")

report = json.loads(report_bytes)
if "errors" not in report or report["errors"] != []:
    raise SystemExit(f"unexpected or missing Semgrep errors: {report.get('errors')!r}")

paths = report.get("paths")
if not isinstance(paths, dict):
    raise SystemExit(f"invalid or missing Semgrep paths object: {paths!r}")
if paths.get("skipped", []) != []:
    raise SystemExit(f"unexpected skipped Semgrep paths: {paths.get('skipped')!r}")

scanned = paths.get("scanned")
if not isinstance(scanned, list) or not all(isinstance(path, str) for path in scanned):
    raise SystemExit(f"invalid or missing scanned Semgrep paths: {scanned!r}")


def normalized_path(raw_path):
    normalized = pathlib.PurePosixPath(raw_path)
    if (
        normalized.is_absolute()
        or ".." in normalized.parts
        or normalized.as_posix() in {"", "."}
    ):
        raise SystemExit(f"unsafe Semgrep path: {raw_path!r}")
    return normalized.as_posix().removeprefix("./")


normalized_scanned = {normalized_path(path) for path in scanned}
expected_scanned = {"clean.c", "vulnerable.c"}
if normalized_scanned != expected_scanned:
    raise SystemExit(
        f"unexpected scanned Semgrep paths: {sorted(normalized_scanned)!r}"
    )

results = report.get("results")
if not isinstance(results, list):
    raise SystemExit(f"invalid or missing Semgrep results: {results!r}")

matching_paths = []
for result in results:
    if not isinstance(result, dict):
        raise SystemExit(f"invalid Semgrep result: {result!r}")
    path = result.get("path")
    if not isinstance(path, str):
        raise SystemExit(f"invalid Semgrep result path: {path!r}")
    normalized = normalized_path(path)
    if normalized not in expected_scanned:
        raise SystemExit(f"Semgrep result path is outside the fixture manifest: {path!r}")
    if normalized == "clean.c":
        raise SystemExit(
            f"clean.c unexpectedly produced result {result.get('check_id')!r}"
        )
    if result.get("check_id") == "raptor-insecure-api-gets":
        matching_paths.append(normalized)

if matching_paths != ["vulnerable.c"]:
    raise SystemExit(
        "expected exactly one raptor-insecure-api-gets result in vulnerable.c "
        f"and none in clean.c, got {matching_paths!r}"
    )

print("Verified regular, symlink-safe, bounded Semgrep JSON")
print("Verified empty errors and absent-or-empty skipped paths")
print("Verified exact scanned fixture manifest: clean.c, vulnerable.c")
print("Verified one raptor-insecure-api-gets result in vulnerable.c")
print("Verified clean.c has no result from any rule")
PY

echo "Verified Semgrep ${SEMGREP_VERSION}"
echo "Verified rules commit ${RULES_COMMIT}"
echo "Verified rules tree digest ${RULES_TREE_SHA256}"
echo "Verified bundled LGPL-2.1 and MIT license files"
