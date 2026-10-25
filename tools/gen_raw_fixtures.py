#!/usr/bin/env python3
"""Generate TA-shaped synthetic HEC /event fixtures from scenario files.

Default: fixtures/raw/scenario.json (NX-OS). --scenario aci: fixtures/raw-aci/scenario.json (ACI pilot).
--scenario networking: fixtures/raw-networking/scenario.json (cross-vendor client flows).

Every event shape follows the installed TA or collector code cited next to its
builder. Field-level provenance and grounding gaps are listed in
fixtures/raw/FIELDS.md and fixtures/raw-aci/FIELDS.md. Output is deterministic.
"""

from __future__ import annotations
from importlib import import_module as _import_module
from types import ModuleType as _ModuleType
import hashlib as _hashlib
import sys as _sys
from pathlib import Path as _Path

_package_name = f"{__package__}.raw_fixtures" if __package__ else "raw_fixtures"
_common = _import_module(f"{_package_name}.common")
_nxos = _import_module(f"{_package_name}.nxos")
_aci = _import_module(f"{_package_name}.aci")
_networking = _import_module(f"{_package_name}.networking")
_cli = _import_module(f"{_package_name}.cli")

# Keep the established import surface while builder responsibilities are modular.
for _source in (_common, _nxos, _aci, _networking, _cli):
    for _symbol in dir(_source):
        if not _symbol.startswith("__"):
            globals()[_symbol] = getattr(_source, _symbol)

ROOT = _common.ROOT
GENERATOR_SOURCE_FILES = (
    "tools/gen_raw_fixtures.py",
    "tools/raw_fixtures/__init__.py",
    "tools/raw_fixtures/common.py",
    "tools/raw_fixtures/nxos.py",
    "tools/raw_fixtures/aci.py",
    "tools/raw_fixtures/networking.py",
    "tools/raw_fixtures/cli.py",
)


def generator_source_hashes(source_root: _Path | None = None) -> dict[str, str]:
    """Return hashes for the complete fixture-generator implementation closure."""
    source_root = source_root or ROOT
    return {
        relative: _hashlib.sha256((source_root / relative).read_bytes()).hexdigest()
        for relative in GENERATOR_SOURCE_FILES
    }


def main(argv: list[str] | None = None) -> int:
    return _cli.main(__doc__, argv)


class _FixtureGeneratorModule(_ModuleType):
    def __setattr__(self, name, value):
        _ModuleType.__setattr__(self, name, value)
        if name.isupper():
            for _target in (_common, _nxos, _aci, _networking, _cli):
                if name in _target.__dict__:
                    setattr(_target, name, value)


_sys.modules[__name__].__class__ = _FixtureGeneratorModule

if __name__ == "__main__":
    raise SystemExit(main())
