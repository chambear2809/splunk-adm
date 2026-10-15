"""Completed UI phase reports must identify their implementation commits."""

from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[1]


class UiPhaseDocumentationTest(unittest.TestCase):
    def test_completed_phase_reports_record_their_commits(self):
        for phase, commit in ((7, "74d8a4a"), (8, "bfda974")):
            with self.subTest(phase=phase):
                text = (ROOT / "docs" / f"UI-PHASE-{phase}.md").read_text()
                introduction = text.split("\n## ", 1)[0]
                self.assertNotIn("uncommitted", introduction.lower())
                self.assertRegex(
                    introduction,
                    rf"Phase {phase} is committed as\s+`{re.escape(commit)}`",
                )
