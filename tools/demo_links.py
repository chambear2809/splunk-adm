"""Write a local, clickable copy of the live-lab demo guide for one Splunk Cloud stack.

The committed guide uses the placeholder ``<stack>`` so the lab stack name is not
published. This writes ``docs/demos/LIVE_LAB_SCENARIOS.local.md`` (git-ignored)
with the placeholder replaced.

Usage: python3 tools/demo_links.py --stack <stack-name>
"""

from __future__ import annotations

import argparse
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
GUIDE = ROOT / "docs/demos/LIVE_LAB_SCENARIOS.md"
LOCAL = ROOT / "docs/demos/LIVE_LAB_SCENARIOS.local.md"
STACK = re.compile(r"^[a-z0-9][a-z0-9-]{1,62}$")


def render(text: str, stack: str) -> str:
    if not STACK.fullmatch(stack):
        raise ValueError("stack must be a Splunk Cloud stack name such as acme-prod")
    return text.replace("<stack>", stack)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--stack", required=True, help="Splunk Cloud stack name")
    args = parser.parse_args(argv)
    LOCAL.write_text(render(GUIDE.read_text(), args.stack))
    print(f"Wrote {LOCAL.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
