"""NX-OS source adapters are gated on a versioned native payload sample.

The normalized ``nxos.device_snapshot`` projection is registered for
``normalized_export_only`` use.  This native adapter remains fail-closed until
a versioned command-response sample is admitted; it does not guess a CLI,
NX-API, DME, Nexus Dashboard, or NDO field mapping from normalized names.
"""

from __future__ import annotations

from typing import Any

from ..contracts import ContractError

PRODUCT = "nxos"
DEVICE_SNAPSHOT_FAMILY = "device_snapshot"


def adapt_nxos_device_snapshots(
    native_records: Any,
    collection_metadata: Any,
) -> dict[str, Any]:
    """Refuse native NX-OS snapshots until a native mapping is admitted.

    ``native_records`` and ``collection_metadata`` are deliberately not read:
    the frozen projection has no versioned command-response sample from which
    to define native identity, field mapping, or complete snapshot boundaries.
    A package-shaped record, synthetic record, or hand-built normalized-looking
    record therefore cannot enter immutable history through this adapter.
    """

    del native_records, collection_metadata
    raise ContractError(
        "source_projection_blocked",
        "NX-OS native snapshot normalization is blocked until a versioned, "
        "sanitized command sample and projection approval are available.",
    )
