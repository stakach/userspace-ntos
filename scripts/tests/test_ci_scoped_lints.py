"""The scoped lint gate fails on findings in scoped crates only."""

import json
from pathlib import Path
import tempfile
import unittest

from scripts.ci_scoped_lints import load_scope, scoped_findings

SCOPED = "path+file:///w/crates/nt-time#0.1.0"
OTHER = "path+file:///w/crates/nt-compat-exports#0.1.0"


def message(package_id, level, rendered, reason="compiler-message"):
    return json.dumps({"reason": reason, "package_id": package_id,
                       "message": {"level": level, "rendered": rendered, "message": rendered}})


class ScopedLintTests(unittest.TestCase):
    def test_only_scoped_warnings_and_errors_are_findings(self):
        lines = [
            message(SCOPED, "warning", "warning: manual div_ceil\n"),
            message(SCOPED, "error", "error: unsafe block missing a safety comment\n"),
            message(SCOPED, "note", "note: for further information\n"),
            message(OTHER, "warning", "warning: dependency finding\n"),
            message(SCOPED, "warning", "ignored", reason="build-finished"),
            "not json",
        ]
        self.assertEqual(scoped_findings(lines, {SCOPED}), [
            "warning: manual div_ceil\n", "error: unsafe block missing a safety comment\n"])

    def test_the_scope_file_ignores_comments_and_rejects_duplicates(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "scope.txt"
            path.write_text("# gated crates\nnt-time\n\nnt-mdl  # small\n")
            self.assertEqual(load_scope(path), ["nt-time", "nt-mdl"])
            path.write_text("nt-time\nnt-time\n")
            with self.assertRaises(ValueError):
                load_scope(path)


if __name__ == "__main__":
    unittest.main()
