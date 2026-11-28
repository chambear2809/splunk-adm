"""Keep Cursor and Codex protocol-agent definitions in sync."""

from __future__ import annotations

import tomllib
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CURSOR_AGENTS = ROOT / ".cursor" / "agents"
CODEX_AGENTS = ROOT / ".codex" / "agents"
CODEX_CONFIG = ROOT / ".codex" / "config.toml"

# Cursor markdown name -> Codex toml file, config.toml table, expected readonly.
ROLES = {
    "code-reviewer": {
        "cursor": "code-reviewer.md",
        "codex": "reviewer.toml",
        "config_key": "reviewer",
        "readonly": True,
    },
    "ux-reviewer": {
        "cursor": "ux-reviewer.md",
        "codex": "ux_reviewer.toml",
        "config_key": "ux_reviewer",
        "readonly": True,
    },
    "protocol-worker": {
        "cursor": "protocol-worker.md",
        "codex": "protocol_worker.toml",
        "config_key": "protocol_worker",
        "readonly": False,
    },
    "ecosystem-worker": {
        "cursor": "ecosystem-worker.md",
        "codex": "ecosystem_worker.toml",
        "config_key": "ecosystem_worker",
        "readonly": False,
    },
}


def parse_cursor_agent(path: Path) -> tuple[dict[str, str], str]:
    text = path.read_text(encoding="utf-8")
    if not text.startswith("---\n"):
        raise ValueError(f"{path} is missing YAML frontmatter")
    rest = text[4:]
    fence = rest.find("\n---\n")
    if fence < 0:
        raise ValueError(f"{path} is missing a closing frontmatter fence")
    raw_meta, body = rest[:fence], rest[fence + 5 :]
    meta: dict[str, str] = {}
    for line in raw_meta.splitlines():
        if not line.strip() or line.lstrip().startswith("#") or ":" not in line:
            continue
        key, value = line.split(":", 1)
        meta[key.strip()] = value.strip()
    return meta, body.strip()


class AgentDefinitionChecks(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.config = tomllib.loads(CODEX_CONFIG.read_text(encoding="utf-8"))
        cls.agents = cls.config.get("agents") or {}

    def test_every_role_exists_in_both_tools_and_is_registered(self) -> None:
        cursor_names = {path.stem for path in CURSOR_AGENTS.glob("*.md")}
        mapped_cursor = set(ROLES)
        self.assertEqual(
            cursor_names,
            mapped_cursor,
            "every .cursor/agents/*.md file needs a ROLES mapping, and every mapped role needs a file",
        )
        for role, spec in ROLES.items():
            cursor_path = CURSOR_AGENTS / spec["cursor"]
            codex_path = CODEX_AGENTS / spec["codex"]
            self.assertTrue(
                cursor_path.is_file(), f"missing Cursor agent {cursor_path}"
            )
            self.assertTrue(codex_path.is_file(), f"missing Codex agent {codex_path}")
            self.assertIn(
                spec["config_key"],
                self.agents,
                f"missing [agents.{spec['config_key']}] in .codex/config.toml for {role}",
            )
            entry = self.agents[spec["config_key"]]
            self.assertEqual(
                Path(entry["config_file"]).name,
                spec["codex"],
                f"[agents.{spec['config_key']}] config_file should point at {spec['codex']}",
            )

    def test_reviewers_are_read_only_in_both_tools(self) -> None:
        for role, spec in ROLES.items():
            cursor_meta, _ = parse_cursor_agent(CURSOR_AGENTS / spec["cursor"])
            codex = tomllib.loads(
                (CODEX_AGENTS / spec["codex"]).read_text(encoding="utf-8")
            )
            cursor_readonly = cursor_meta.get("readonly", "false").lower() == "true"
            codex_readonly = str(codex.get("sandbox_mode", "")).lower() == "read-only"
            if spec["readonly"]:
                self.assertTrue(
                    cursor_readonly, f"{role} Cursor agent must set readonly: true"
                )
                self.assertTrue(
                    codex_readonly,
                    f'{role} Codex agent must set sandbox_mode = "read-only"',
                )
            else:
                self.assertFalse(
                    cursor_readonly, f"{role} Cursor agent must not be read-only"
                )
                self.assertFalse(
                    codex_readonly,
                    f"{role} Codex agent must not be read-only",
                )

    def test_instruction_text_does_not_drift(self) -> None:
        for role, spec in ROLES.items():
            _, cursor_body = parse_cursor_agent(CURSOR_AGENTS / spec["cursor"])
            codex = tomllib.loads(
                (CODEX_AGENTS / spec["codex"]).read_text(encoding="utf-8")
            )
            codex_body = str(codex.get("developer_instructions", "")).strip()
            self.assertEqual(
                cursor_body,
                codex_body,
                f"{role} instruction text drifted between Cursor and Codex",
            )

    def test_cursor_models_match_the_operating_contract(self) -> None:
        expected = {
            "code-reviewer": "claude-opus-5-5-medium",
            "ux-reviewer": "claude-opus-5-5-medium",
            "protocol-worker": "gemini-4-hydrogen",
            "ecosystem-worker": "gemini-4-hydrogen",
        }
        for name, model in expected.items():
            meta, _ = parse_cursor_agent(CURSOR_AGENTS / f"{name}.md")
            self.assertEqual(meta.get("model"), model, f"{name} Cursor model")


if __name__ == "__main__":
    unittest.main()
