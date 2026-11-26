"""Owner-generated local authorization for connected scenario acquisition."""
from __future__ import annotations

import hashlib
import os
import re
import stat
from pathlib import Path
from typing import Any

from tools.change_correlation.contracts import canonical_json

HASH_RE = re.compile(r"^[a-f0-9]{64}$")
TASK_RE = re.compile(r"^[a-z0-9][a-z0-9-]{2,63}$")


class AuthorizationError(ValueError):
    pass


def _sha(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _digest(value: Any, label: str) -> str:
    if not isinstance(value, str) or not HASH_RE.fullmatch(value):
        raise AuthorizationError(f"{label} must be a SHA-256 digest.")
    return value


def issue_run_authorization(
    plan: dict[str, Any],
    *,
    task_id: str,
    approved_queries: list[dict[str, Any]],
    issued_epoch: int,
) -> dict[str, Any]:
    if not isinstance(task_id, str) or not TASK_RE.fullmatch(task_id):
        raise AuthorizationError("Task ID is invalid.")
    plan_hash = _digest(plan.get("plan_sha256"), "plan_sha256")
    if _sha(canonical_json({k: v for k, v in plan.items() if k != "plan_sha256"})) != plan_hash:
        raise AuthorizationError("Plan body does not match its immutable hash.")
    if not isinstance(approved_queries, list) or not approved_queries:
        raise AuthorizationError("Approved query set is empty.")
    queries = []
    seen = set()
    for item in approved_queries:
        if not isinstance(item, dict) or set(item) != {"name", "sha256", "earliest", "latest"}:
            raise AuthorizationError("Approved query entry has unsupported fields.")
        name = item["name"]
        digest = _digest(item["sha256"], "query sha256")
        if not isinstance(name, str) or not name or name in seen:
            raise AuthorizationError("Approved query names must be unique text.")
        if not isinstance(item["earliest"], (int, float)) or not isinstance(item["latest"], (int, float)) or item["earliest"] > item["latest"]:
            raise AuthorizationError("Approved query window is invalid.")
        seen.add(name)
        queries.append({"name": name, "sha256": digest, "earliest": item["earliest"], "latest": item["latest"]})
    body = {
        "schema_version": 1,
        "kind": "local_connected_run_authorization_v1",
        "task_id": task_id,
        "scenario_id": plan.get("scenario_id"),
        "execution_id": plan.get("execution_id"),
        "plan_sha256": plan_hash,
        "approved_queries": sorted(queries, key=lambda item: item["name"]),
        "issued_epoch": issued_epoch,
    }
    return {**body, "authorization_sha256": _sha(canonical_json(body))}


def verify_run_authorization(
    authorization: Any,
    *,
    expected_task_id: str,
    expected_plan_sha256: str,
    expected_execution_id: str,
    expected_queries: list[dict[str, Any]],
) -> dict[str, Any]:
    if not isinstance(authorization, dict) or authorization.get("kind") != "local_connected_run_authorization_v1":
        raise AuthorizationError("Authorization kind is unsupported.")
    body = {k: v for k, v in authorization.items() if k != "authorization_sha256"}
    if authorization.get("authorization_sha256") != _sha(canonical_json(body)):
        raise AuthorizationError("Authorization hash does not match content.")
    if (
        authorization.get("task_id") != expected_task_id
        or authorization.get("plan_sha256") != expected_plan_sha256
        or authorization.get("execution_id") != expected_execution_id
    ):
        raise AuthorizationError("Authorization is not bound to the expected run.")
    _digest(authorization.get("plan_sha256"), "authorization plan_sha256")
    queries = authorization.get("approved_queries")
    if not isinstance(queries, list) or not queries:
        raise AuthorizationError("Authorization query set is empty.")
    if sorted(queries, key=lambda item: item.get("name", "")) != sorted(expected_queries, key=lambda item: item.get("name", "")):
        raise AuthorizationError("Authorization queries differ from independent approval.")
    for item in queries:
        if not isinstance(item, dict) or set(item) != {"name", "sha256", "earliest", "latest"}:
            raise AuthorizationError("Authorization query entry is malformed.")
        _digest(item.get("sha256"), "authorization query sha256")
        if not isinstance(item.get("earliest"), (int, float)) or not isinstance(item.get("latest"), (int, float)) or item["earliest"] > item["latest"]:
            raise AuthorizationError("Authorization query window is invalid.")
    return authorization


def write_private_authorization(path: Path, authorization: dict[str, Any]) -> None:
    """Write once into a caller-owned private task directory."""
    if path.exists() or path.is_symlink() or path.name in {"", ".", ".."}:
        raise AuthorizationError("Authorization path already exists.")
    if not path.is_absolute():
        raise AuthorizationError("Authorization path must be absolute.")
    data = canonical_json(authorization)
    parent_fd = os.open(path.anchor, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        components = [part for part in path.parent.parts if part not in {path.anchor, ""}]
        for index, part in enumerate(components):
            try:
                next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent_fd)
            except FileNotFoundError:
                os.mkdir(part, 0o700, dir_fd=parent_fd)
                next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent_fd)
            except OSError as exc:
                raise AuthorizationError("Authorization parent cannot be opened safely.") from exc
            info = os.fstat(next_fd)
            if index == len(components) - 1 and (info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o077):
                os.close(next_fd)
                raise AuthorizationError("Authorization parent is not private and owner-controlled.")
            os.close(parent_fd)
            parent_fd = next_fd
    except Exception:
        os.close(parent_fd)
        raise
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    try:
        fd = os.open(path.name, flags | os.O_NOFOLLOW, 0o600, dir_fd=parent_fd)
    except OSError as exc:
        os.close(parent_fd)
        raise AuthorizationError("Authorization file could not be created safely.") from exc
    try:
        offset = 0
        while offset < len(data):
            written = os.write(fd, data[offset:])
            if written <= 0:
                raise AuthorizationError("Authorization write made no progress.")
            offset += written
        file_info = os.fstat(fd)
        if file_info.st_uid != os.getuid() or stat.S_IMODE(file_info.st_mode) != 0o600:
            raise AuthorizationError("Authorization file permissions are not private.")
    finally:
        os.close(fd)
        os.close(parent_fd)
