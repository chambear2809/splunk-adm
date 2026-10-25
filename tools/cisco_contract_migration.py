#!/usr/bin/env python3
"""Stage and verify the Application Atlas summary contract v2 on standalone Splunk.

The tool is deliberately conservative. It uses a local, durable journal and
Splunk's TLS-verified local management REST API. It never accepts a token as an
argument, never retries an ambiguous search dispatch, and never changes the
legacy summary index macro.
"""

from __future__ import annotations
from importlib import import_module as _import_module
from types import ModuleType as _ModuleType
import sys as _sys

_package_name = f"{__package__}.cisco_migration" if __package__ else "cisco_migration"
_common = _import_module(f"{_package_name}.common")
_journal = _import_module(f"{_package_name}.journal")
_cli = _import_module(f"{_package_name}.cli")
_core = _import_module(f"{_package_name}.core")
_evidence = _import_module(f"{_package_name}.evidence")
_dispatch = _import_module(f"{_package_name}.dispatch")
_history = _import_module(f"{_package_name}.history")
_cutover = _import_module(f"{_package_name}.cutover")
_recovery = _import_module(f"{_package_name}.recovery")

# Retain the original import surface while responsibilities live in private modules.
for _source in (_common, _journal, _cli):
    for _symbol in dir(_source):
        if not _symbol.startswith("__"):
            globals()[_symbol] = getattr(_source, _symbol)

_api_from_stdin = _cli._api_from_stdin
_read_scenario = _cli._read_scenario
Journal = _journal.Journal


class Migration(
    _core.MigrationCore,
    _evidence.MigrationEvidence,
    _dispatch.MigrationDispatch,
    _history.MigrationHistory,
    _cutover.MigrationCutover,
    _recovery.MigrationRecovery,
):
    """Injectable orchestration for staged v2 summary backfill and cutover."""


def main(argv: list[str] | None = None) -> int:
    return _cli.main(
        argv,
        api_factory=_api_from_stdin,
        migration_class=Migration,
        description=__doc__,
    )


# Preserve the legacy unittest.mock.patch seam for extracted safety limits.
class _MigrationModule(_ModuleType):
    def __setattr__(self, name, value):
        _ModuleType.__setattr__(self, name, value)
        if name.isupper():
            for _target in (
                _common,
                _journal,
                _core,
                _evidence,
                _dispatch,
                _history,
                _cutover,
                _recovery,
                _cli,
            ):
                if name in _target.__dict__:
                    setattr(_target, name, value)


_sys.modules[__name__].__class__ = _MigrationModule

if __name__ == "__main__":
    raise SystemExit(main())
