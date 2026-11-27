"""Unit tests for [adm_change_request_window(1)] macro diagnostics."""

from __future__ import annotations

import pathlib
import re
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
MACROS_PATH = ROOT / "splunk_app" / "splunk_adm" / "default" / "macros.conf"


def _extract_stanza(text: str, name: str) -> str:
    header = f"[{name}]"
    lines = text.splitlines()
    start = None
    for idx, line in enumerate(lines):
        if line.strip() == header:
            start = idx
            break
    if start is None:
        raise AssertionError(f"missing stanza [{name}]")
    end = len(lines)
    for idx in range(start + 1, len(lines)):
        if re.match(r"^\[[^\]]+\]\s*$", lines[idx]):
            end = idx
            break
    return "\n".join(lines[start:end])


class ChangeRequestWindowMacroTest(unittest.TestCase):
    def test_preserves_diagnostic_row_when_all_updates_invalid(self):
        text = MACROS_PATH.read_text(encoding="utf-8")
        stanza = _extract_stanza(text, "adm_change_request_window(1)")

        # Initialize row_type before appendpipe so raw events cannot spoof diagnostic rows.
        init_idx = stanza.index('row_type="change_request"')
        append_idx = stanza.index("| appendpipe [")
        filter_idx = stanza.index(
            '| where adm_valid_update==1 OR row_type=="change_request_invalid"'
        )
        self.assertLess(init_idx, append_idx)
        self.assertLess(append_idx, filter_idx)

        self.assertIn("where adm_read>0 AND adm_valid_count==0", stanza)
        self.assertIn('row_type="change_request_invalid"', stanza)
        self.assertIn("records_capped=if(adm_read>500, 1, 0)", stanza)
        self.assertIn("invalid_updates", stanza)
        self.assertIn("| dedup sys_id keepempty=true", stanza)
        self.assertIn("| head 4", stanza)


if __name__ == "__main__":
    unittest.main()
