"""The sandbox image ships its notices and the Ubuntu snapshot time it was built at."""

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DOCKERFILE = (ROOT / "docker/sandbox/Dockerfile").read_text(encoding="utf-8")
NOTICES = (ROOT / "docker/sandbox/NOTICES.md").read_text(encoding="utf-8")
BUILD_SCRIPT = (ROOT / "scripts/build-sandbox.sh").read_text(encoding="utf-8")
NOTICE_DIR = "/usr/share/doc/oxfuzz-sandbox"
TIMESTAMP = re.compile(r"[0-9]{8}T[0-9]{6}Z")


class SandboxNoticesTest(unittest.TestCase):
    def test_first_apt_layer_records_the_snapshot_time(self):
        record = DOCKERFILE.index(f"{NOTICE_DIR}/ubuntu-snapshot.txt")
        self.assertLess(record, DOCKERFILE.index("&& apt-get update"))
        self.assertIn("+%Y%m%dT%H%M%SZ", DOCKERFILE)

    def test_image_build_and_smoke_check_validate_the_timestamp_format(self):
        pattern = "[0-9]{8}T[0-9]{6}Z"
        self.assertIn(pattern, DOCKERFILE)
        self.assertIn(pattern, BUILD_SCRIPT)
        self.assertIsNotNone(TIMESTAMP.fullmatch("20261124T070000Z"))
        self.assertIsNone(TIMESTAMP.fullmatch("2026-11-24"))

    def test_notices_name_the_shipped_files_and_source_location(self):
        for needle in (
            "ubuntu-snapshot.txt",
            "packages.tsv",
            "Types: deb-src",
            "URIs: https://snapshot.ubuntu.com/ubuntu/<timestamp>/",
            "Suites: noble noble-updates noble-security",
            "not version-pinned",
            "Written offer",
            "three years",
            "issue tracker",
        ):
            self.assertIn(needle, NOTICES)

    def test_notices_have_no_open_maintainer_items(self):
        self.assertNotIn("MAINTAINER TO CONFIRM", NOTICES)

    def test_dockerfile_copies_notices_and_licences(self):
        self.assertIn(f"{NOTICE_DIR}/NOTICES.md", DOCKERFILE)
        for text in ("GPL-2", "GPL-3", "LGPL-2.1", "LGPL-3"):
            self.assertIn(text, DOCKERFILE)


if __name__ == "__main__":
    unittest.main()
