"""Compatibility exports for the recovery planner used by repository tools."""

from splunk_app.splunk_adm.bin.adm_recovery_lib.planner import (
    TARGET_WINDOWS,
    build_recovery_plan,
    validate_recovery_plan,
)

__all__ = ["TARGET_WINDOWS", "build_recovery_plan", "validate_recovery_plan"]
