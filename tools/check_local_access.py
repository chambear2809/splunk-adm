#!/usr/bin/env python3
"""Validate local, operator-owned access configuration without connecting.

This module deliberately treats credentials as data.  It never invokes a
shell, expands variables, prints values, or makes a network request.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
from typing import Any
from urllib.parse import urlsplit

PROFILES = ("cloud", "hf", "enterprise")
FIELDS = {
    "SPLUNK_PLATFORM",
    "SPLUNK_TARGET_ROLE",
    "SPLUNK_SEARCH_API_URI",
    "SPLUNK_URI",
    "SPLUNK_HOST",
    "SPLUNK_MGMT_PORT",
    "SPLUNK_USER",
    "SPLUNK_PASS",
    "SPLUNK_VERIFY_SSL",
    "SPLUNK_CLOUD_STACK",
    "SPLUNK_SSH_HOST",
    "SPLUNK_SSH_USER",
    "SPLUNK_SSH_KNOWN_HOSTS_FILE",
    "SPLUNK_SSH_AUTH_METHOD",
    "SPLUNK_SSH_ALLOW_TOFU",
    "SPLUNK_CA_CERT",
    "SPLUNK_ALLOW_INSECURE_HTTP",
    "SPLUNK_ACS_SERVER",
    "SPLUNK_STACK_TOKEN",
    "SPLUNK_STACK_TOKEN_USER",
    "SPLUNK_HEC_TOKEN_FILE",
    "SPLUNK_HEC_URL",
    "ACS_SERVER",
    "STACK_TOKEN",
    "STACK_TOKEN_USER",
}
ROLES = {"cloud": "search-tier", "hf": "heavy-forwarder", "enterprise": "standalone"}
PROFILE_KEY = re.compile(r"^PROFILE_(cloud|hf|enterprise)__([A-Z][A-Z0-9_]*)$")
EXPECTATION_FIELDS = {"ssh_host", "search_uri", "ca_path", "hec_url"}


def _regular_owner_file(path: Path) -> tuple[bool, str | None]:
    try:
        st = path.lstat()
    except OSError:
        return False, "missing_file"
    if stat.S_ISLNK(st.st_mode):
        return False, "symlink_forbidden"
    if not stat.S_ISREG(st.st_mode):
        return False, "not_regular_file"
    if st.st_uid != os.getuid():
        return False, "wrong_owner"
    if st.st_mode & 0o077:
        return False, "permissions_not_owner_only"
    return True, None


def _value(raw: str) -> str:
    raw = raw.strip()
    if raw.startswith('"'):
        try:
            value = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise ValueError("invalid_quoted_value") from exc
        if not isinstance(value, str):
            raise ValueError("value_not_string")
    else:
        value = raw
    if any(ord(char) < 32 or ord(char) == 127 for char in value):
        raise ValueError("unsafe_value")
    return value


def parse_credentials(path: Path) -> tuple[dict[str, dict[str, str]], list[str]]:
    """Parse PROFILE_* static assignments, returning only non-secret errors."""
    ok, error = _regular_owner_file(path)
    if not ok:
        return {}, [error or "invalid_file"]
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError):
        return {}, ["unreadable_file"]
    if len(text) > 64 * 1024:
        return {}, ["file_too_large"]
    profiles: dict[str, dict[str, str]] = {p: {} for p in PROFILES}
    errors: list[str] = []
    seen: set[str] = set()
    default_seen = False
    for lineno, line in enumerate(text.splitlines(), 1):
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if "=" not in line:
            errors.append("invalid_line")
            continue
        key, raw = line.split("=", 1)
        key = key.strip()
        if key == "SPLUNK_PROFILE":
            if default_seen:
                errors.append("duplicate_key")
                continue
            default_seen = True
            try:
                if _value(raw) != "enterprise":
                    errors.append("default_profile_mismatch")
            except ValueError as exc:
                errors.append(str(exc))
            continue
        match = PROFILE_KEY.fullmatch(key)
        if not match or not (
            match.group(2).startswith("SPLUNK_")
            or match.group(2) in {"ACS_SERVER", "STACK_TOKEN", "STACK_TOKEN_USER"}
        ):
            errors.append("invalid_key")
            continue
        if match.group(2) not in FIELDS:
            errors.append("unknown_field")
            continue
        if key in seen:
            errors.append("duplicate_key")
            continue
        seen.add(key)
        try:
            profiles[match.group(1)][match.group(2)] = _value(raw)
        except ValueError as exc:
            errors.append(str(exc))
    if not default_seen:
        errors.append("missing_splunk_profile")
    return profiles, sorted(set(errors))


def _profile_errors(
    name: str,
    cfg: dict[str, str],
    expectations: dict[str, dict[str, str]] | None = None,
) -> list[str]:
    def get(*keys: str) -> str:
        for key in keys:
            if cfg.get(key) is not None:
                return cfg[key]
        return ""

    required = {
        "SPLUNK_PLATFORM",
        "SPLUNK_TARGET_ROLE",
        "SPLUNK_USER",
        "SPLUNK_PASS",
        "SPLUNK_VERIFY_SSL",
    }
    if not get("SPLUNK_URI", "SPLUNK_SEARCH_API_URI"):
        errors = ["missing_splunk_uri"]
    else:
        errors = []
    if (
        cfg.get("SPLUNK_URI")
        and cfg.get("SPLUNK_SEARCH_API_URI")
        and cfg["SPLUNK_URI"] != cfg["SPLUNK_SEARCH_API_URI"]
    ):
        errors.append("uri_alias_conflict")
    if name in ("hf", "enterprise"):
        required |= {
            "SPLUNK_SSH_HOST",
            "SPLUNK_SSH_USER",
            "SPLUNK_SSH_KNOWN_HOSTS_FILE",
            "SPLUNK_SSH_AUTH_METHOD",
            "SPLUNK_SSH_ALLOW_TOFU",
        }
    errors += [
        f"missing_{field.lower()}" for field in sorted(required) if not cfg.get(field)
    ]
    expected_platform = "cloud" if name == "cloud" else "enterprise"
    if cfg.get("SPLUNK_PLATFORM") != expected_platform:
        errors.append("platform_mismatch")
    if cfg.get("SPLUNK_TARGET_ROLE") != ROLES[name]:
        errors.append("target_role_mismatch")
    if get("SPLUNK_VERIFY_SSL").lower() != "true":
        errors.append("verify_ssl_required")
    if name != "cloud":
        if cfg.get("SPLUNK_SSH_AUTH_METHOD") != "key":
            errors.append("ssh_key_auth_required")
        if cfg.get("SPLUNK_SSH_ALLOW_TOFU", "").lower() != "false":
            errors.append("tofu_forbidden")
    if name == "cloud":
        stack = cfg.get("SPLUNK_CLOUD_STACK", "")
        if (
            not stack
            or stack.endswith(".")
            or not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?", stack)
        ):
            errors.append("invalid_stack")
        if any(
            cfg.get(k)
            for k in (
                "SPLUNK_SSH_HOST",
                "SPLUNK_SSH_USER",
                "SPLUNK_SSH_KNOWN_HOSTS_FILE",
                "SPLUNK_SSH_AUTH_METHOD",
                "SPLUNK_SSH_ALLOW_TOFU",
                "SPLUNK_CA_CERT",
            )
        ):
            errors.append("cloud_ssh_leakage")
        if (
            stack
            and get("SPLUNK_URI", "SPLUNK_SEARCH_API_URI")
            != f"https://{stack}.splunkcloud.com:8089"
        ):
            errors.append("cloud_endpoint_mismatch")
        if cfg.get("SPLUNK_HEC_URL"):
            errors.append("cloud_hec_forbidden")
    else:
        ca = cfg.get("SPLUNK_CA_CERT", "")
        if ca and not ca.startswith("/"):
            errors.append("ca_path_not_remote")
    for field, actual in {
        "ssh_host": cfg.get("SPLUNK_SSH_HOST", ""),
        "search_uri": get("SPLUNK_URI", "SPLUNK_SEARCH_API_URI"),
        "ca_path": cfg.get("SPLUNK_CA_CERT", ""),
        "hec_url": cfg.get("SPLUNK_HEC_URL", ""),
    }.items():
        expected = (expectations or {}).get(name, {}).get(field)
        if expected is not None and actual != expected:
            errors.append(f"{name}_{field}_mismatch")
    uri = get("SPLUNK_URI", "SPLUNK_SEARCH_API_URI")
    try:
        parsed = urlsplit(uri)
        port = parsed.port
    except ValueError:
        errors.append("search_uri_malformed")
        return sorted(set(errors))
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
        or parsed.path not in ("", "/")
    ):
        errors.append("search_uri_not_strict_https")
    if name == "cloud" and port not in (8089, None):
        errors.append("search_uri_port_invalid")
    return sorted(set(errors))


def validate_credentials(
    path: Path, expectations: dict[str, dict[str, str]] | None = None
) -> dict[str, Any]:
    profiles, parse_errors = parse_credentials(path)
    result = {}
    for name in PROFILES:
        cfg = profiles.get(name, {})
        profile_errors = _profile_errors(name, cfg, expectations)
        result[name] = {
            "valid": not parse_errors and not profile_errors,
            "errors": sorted(set(parse_errors + profile_errors)),
        }
    return {
        "default_profile": "enterprise",
        "profiles": result,
        "target_expectations": {
            "provided": expectations is not None,
            "profile_keys_asserted": sorted(expectations or {}),
        },
    }


def parse_expectations(path: Path) -> tuple[dict[str, dict[str, str]], list[str]]:
    """Read nonsecret target assertions from an owner-only JSON file."""
    ok, error = _regular_owner_file(path)
    if not ok:
        return {}, [error or "invalid_file"]
    try:
        text = path.read_text(encoding="utf-8")
        if len(text) > 16 * 1024:
            return {}, ["file_too_large"]

        def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
            result: dict[str, Any] = {}
            for key, value in pairs:
                if key in result:
                    raise ValueError("duplicate_expectation_key")
                result[key] = value
            return result

        document = json.loads(text, object_pairs_hook=reject_duplicates)
    except ValueError as exc:
        if str(exc) == "duplicate_expectation_key":
            return {}, [str(exc)]
        return {}, ["invalid_expectations_json"]
    except (OSError, UnicodeError, json.JSONDecodeError):
        return {}, ["invalid_expectations_json"]
    if not isinstance(document, dict):
        return {}, ["invalid_expectations_shape"]
    if "profiles" not in document:
        return {}, ["missing_expectations_profiles"]
    if set(document) != {"profiles"}:
        return {}, ["unknown_expectations_field"]
    profiles = document["profiles"]
    if not isinstance(profiles, dict):
        return {}, ["invalid_expectations_profiles"]
    if any(name not in PROFILES for name in profiles):
        return {}, ["unknown_expectation_profile"]
    result: dict[str, dict[str, str]] = {}
    for name, values in profiles.items():
        if not isinstance(values, dict) or any(
            key not in EXPECTATION_FIELDS for key in values
        ):
            return {}, ["invalid_expectations_field"]
        if any(not isinstance(value, str) or not value for value in values.values()):
            return {}, ["invalid_expectations_value"]
        result[name] = dict(values)
    return result, []


def validate_kubeconfig(path: Path, kubectl: str = "kubectl") -> dict[str, Any]:
    ok, error = _regular_owner_file(path)
    if not ok:
        return {"valid": False, "errors": [error or "invalid_file"]}
    try:
        proc = subprocess.run(
            [kubectl, "--kubeconfig", str(path), "config", "view", "-o", "json"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return {"valid": False, "errors": ["kubectl_unavailable"]}
    if proc.returncode != 0:
        return {"valid": False, "errors": ["kubectl_failed"]}
    try:
        doc = json.loads(proc.stdout)
    except (TypeError, json.JSONDecodeError):
        return {"valid": False, "errors": ["invalid_kubeconfig_json"]}
    if not isinstance(doc, dict):
        return {"valid": False, "errors": ["invalid_kubeconfig_shape"]}
    errors: list[str] = []
    clusters = {
        x.get("name"): x.get("cluster", {})
        for x in (doc.get("clusters") if isinstance(doc.get("clusters"), list) else [])
        if isinstance(x, dict)
    }
    users = {
        x.get("name"): x.get("user", {})
        for x in (doc.get("users") if isinstance(doc.get("users"), list) else [])
        if isinstance(x, dict)
    }
    contexts = {
        x.get("name"): x.get("context", {})
        for x in (doc.get("contexts") if isinstance(doc.get("contexts"), list) else [])
        if isinstance(x, dict)
    }
    for user in users.values():
        if "exec" in user or "auth-provider" in user:
            errors.append("exec_auth_provider_forbidden")
    current = doc.get("current-context")
    context = contexts.get(current)
    if not isinstance(context, dict):
        context = None
    if (
        not context
        or context.get("cluster") not in clusters
        or context.get("user") not in users
    ):
        errors.append("context_incoherent")
    cluster = clusters.get(context.get("cluster")) if context else None
    if not isinstance(cluster, dict) or not str(cluster.get("server", "")).startswith(
        "https://"
    ):
        errors.append("cluster_https_required")
    if not cluster or cluster.get("insecure-skip-tls-verify") is True:
        errors.append("insecure_tls_forbidden")
    if not cluster or not (
        cluster.get("certificate-authority-data")
        or cluster.get("certificate-authority")
    ):
        errors.append("cluster_ca_required")
    return {"valid": not errors, "errors": sorted(set(errors))}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--credentials",
        type=Path,
        default=Path.home() / ".splunk/splunk-adm/credentials",
    )
    parser.add_argument(
        "--kubeconfig", type=Path, default=Path.home() / ".kube/splunk-adm/config"
    )
    parser.add_argument(
        "--expectations",
        type=Path,
        help="owner-only nonsecret JSON target assertions; omitted for portable generic checks",
    )
    parser.add_argument("--skip-kubeconfig", action="store_true")
    args = parser.parse_args(argv)
    expectations: dict[str, dict[str, str]] | None = None
    expectation_errors: list[str] = []
    if args.expectations:
        expectations, expectation_errors = parse_expectations(args.expectations)
    output: dict[str, Any] = {
        "credentials": validate_credentials(args.credentials, expectations)
    }
    output["credentials"]["target_expectations"].update(
        {
            "valid": not expectation_errors,
            "errors": expectation_errors,
        }
    )
    if expectation_errors:
        for profile in output["credentials"]["profiles"].values():
            profile["valid"] = False
            profile["errors"] = sorted(set(profile["errors"] + expectation_errors))
    if not args.skip_kubeconfig:
        output["kubeconfig"] = validate_kubeconfig(args.kubeconfig)
    print(json.dumps(output, sort_keys=True))
    valid = all(p["valid"] for p in output["credentials"]["profiles"].values())
    valid = valid and (args.skip_kubeconfig or output["kubeconfig"]["valid"])
    return 0 if valid else 2


if __name__ == "__main__":
    sys.exit(main())
