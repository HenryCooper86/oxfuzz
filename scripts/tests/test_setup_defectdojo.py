#!/usr/bin/env python3
"""Security regression tests for the local DefectDojo provisioner."""

import pathlib
import re
import subprocess
import unittest


REPOSITORY_ROOT = pathlib.Path(__file__).resolve().parents[2]
SETUP_SCRIPT = REPOSITORY_ROOT / "scripts" / "setup-defectdojo.sh"


class DefectDojoSetupTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.script = SETUP_SCRIPT.read_text(encoding="utf-8")

    def test_shell_syntax_is_valid(self) -> None:
        result = subprocess.run(
            ["bash", "-n", str(SETUP_SCRIPT)],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_upstream_checkout_is_bound_to_an_exact_commit(self) -> None:
        match = re.search(
            r'^DEFAULT_DEFECTDOJO_REF="([0-9a-f]{40})"$',
            self.script,
            flags=re.MULTILINE,
        )
        self.assertIsNotNone(match, "provisioner needs a reviewed immutable default")
        self.assertNotIn("git -C \"$DD_DIR\" pull", self.script)
        self.assertIn('git checkout --detach "$DEFECTDOJO_REF"', self.script)
        self.assertIn('rev-parse HEAD', self.script)

    def test_checkout_environment_override_must_also_be_a_commit(self) -> None:
        self.assertIn("validate_commit_ref", self.script)
        self.assertRegex(
            self.script,
            r"\[\[ \"\$1\" =~ \^\[0-9a-f\]\{40\}\$ \]\]",
        )

    def test_defectdojo_application_images_are_digest_pinned(self) -> None:
        for compose_variable, variable in [
            ("DJANGO_VERSION", "DJANGO_IMAGE_VERSION"),
            ("NGINX_VERSION", "NGINX_IMAGE_VERSION"),
        ]:
            match = re.search(
                rf'^{variable}="[0-9.]+@sha256:[0-9a-f]{{64}}"$',
                self.script,
                flags=re.MULTILINE,
            )
            self.assertIsNotNone(match, f"{variable} must identify reviewed image content")
            self.assertIn(f'{compose_variable}="${variable}"', self.script)

    def test_checkout_env_is_parsed_as_data_not_executed(self) -> None:
        self.assertNotRegex(self.script, r"(?:^|[; ])(?:source|\.)[ ]+\"?\$DD_ENV")
        self.assertIn("read_env_value", self.script)

    def test_secret_files_are_owner_only_and_password_is_not_logged(self) -> None:
        self.assertIn("umask 077", self.script)
        self.assertIn('chmod 600 "$DD_ENV"', self.script)
        self.assertIn('chmod 600 "$CONFIG_FILE"', self.script)
        self.assertNotIn("Admin pass:", self.script)

    def test_api_password_is_sent_on_stdin_not_in_curl_arguments(self) -> None:
        self.assertIn("--data-binary @-", self.script)
        self.assertNotRegex(self.script, r"curl[^\n]*[ ]-d[ ]")


if __name__ == "__main__":
    unittest.main()
