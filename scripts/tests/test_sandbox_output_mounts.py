"""The sandbox verification scripts work for a normal user on native Linux.

The container's root user has every capability dropped, so on a Linux host
without ownership mapping it can write only to a world-writable directory. Each
script keeps its private mktemp root and mounts a 0777 directory inside it.
"""

import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def script(name):
    return (ROOT / "scripts" / name).read_text(encoding="utf-8")


class SandboxOutputMountTest(unittest.TestCase):
    def test_build_script_mounts_a_world_writable_directory_inside_its_private_root(self):
        text = script("build-sandbox.sh")
        self.assertIn('verification_mount="${verification_output}/output"', text)
        self.assertIn('mkdir -m 0777 "$verification_mount"', text)
        self.assertIn('src=$(host_path "$verification_mount"),dst=/work/output', text)
        self.assertNotIn('src=$(host_path "$verification_output"),dst=/work/output', text)
        self.assertLess(text.index('mktemp -d'), text.index('mkdir -m 0777'))

    def test_semgrep_smoke_script_opens_only_the_directories_it_mounts(self):
        text = script("test-semgrep-sandbox.sh")
        self.assertIn('mkdir -m 0777 "$output_root"', text)
        self.assertIn('mkdir -m 0755 "$source_root"', text)
        self.assertIn('output_root="${verification_root}/output"', text)
        self.assertIn('chmod 0644 "$source_root/vulnerable.c" "$source_root/clean.c"', text)


if __name__ == "__main__":
    unittest.main()
