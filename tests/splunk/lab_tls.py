"""Private, task-scoped loopback TLS for newly created disposable labs.

No network discovery or Docker operations occur here. The caller installs the
private server bundle into its verified task-owned container via stdin. Never
print or return key contents in logs or command arguments.
"""

from __future__ import annotations

import json
import os
import re
import secrets
import shutil
import ssl
import stat
import subprocess
from pathlib import Path


class LabTLSError(RuntimeError):
    """The local task TLS material is absent, unsafe, or invalid."""


_FILES = frozenset({"identity.json", "ca.pem", "server.pem"})
_CONTAINER_FILE = "container-id"
_SCRATCH = frozenset(
    {
        "ca.key",
        "ca.pem",
        "leaf.key",
        "leaf.csr",
        "leaf.crt",
        "leaf.ext",
        "server.pem",
        "identity.json",
    }
)


def _identity(task, name):
    if (
        not isinstance(task, str)
        or not re.fullmatch(r"[a-z0-9-]+", task)
        or len(task) > 128
        or not isinstance(name, str)
        or not re.fullmatch(r"adm-[a-z0-9](?:[a-z0-9-]{0,57}[a-z0-9])?", name)
        or name == "adm-splunk-lab"
    ):
        raise LabTLSError("invalid task identity")
    return {"schema": 1, "task": task, "name": name}


def _directory(secrets_path):
    try:
        path = Path(secrets_path)
        if (
            not path.is_absolute()
            or not path.name
            or path.name in (".", "..")
            or not path.parent.is_dir()
            or path.parent.is_symlink()
        ):
            raise LabTLSError("invalid TLS location")
        info = path.parent.stat()
        if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o077:
            raise LabTLSError("TLS runtime directory must be private")
        parent = path.parent.resolve()
        if any((ancestor / ".git").exists() for ancestor in (parent, *parent.parents)):
            raise LabTLSError("TLS material must be outside a Git worktree")
        return path.with_name(path.name + ".tls")
    except (ValueError, TypeError, OSError) as exc:
        raise LabTLSError("invalid TLS location") from exc


def _safe_directory(path):
    try:
        info = path.lstat()
        return (
            stat.S_ISDIR(info.st_mode)
            and info.st_uid == os.getuid()
            and stat.S_IMODE(info.st_mode) == 0o700
        )
    except OSError:
        return False


def _read_private(path, limit=131072):
    descriptor = None
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        info = os.fstat(descriptor)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) != 0o600
            or info.st_nlink != 1
        ):
            raise LabTLSError("unsafe TLS file")
        with os.fdopen(descriptor, "rb") as stream:
            descriptor = None
            value = stream.read(limit + 1)
        if not value or len(value) > limit:
            raise LabTLSError("invalid TLS file")
        return value
    except (OSError, ValueError) as exc:
        raise LabTLSError("unsafe TLS file") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _write_private(path, value):
    fd = os.open(
        path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600
    )
    with os.fdopen(fd, "wb") as stream:
        os.fchmod(stream.fileno(), 0o600)
        stream.write(value)


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise LabTLSError("invalid TLS identity")
        result[key] = value
    return result


def _verify_directory(path, task, name):
    expected = _identity(task, name)
    if not _safe_directory(path):
        raise LabTLSError("unsafe TLS directory")
    try:
        entries = {item.name for item in path.iterdir()}
        if entries not in (_FILES, _FILES | {_CONTAINER_FILE}):
            raise LabTLSError("invalid TLS directory contents")
        actual = json.loads(
            _read_private(path / "identity.json", 1024), object_pairs_hook=_pairs
        )
        if (
            not isinstance(actual, dict)
            or type(actual.get("schema")) is not int
            or actual != expected
        ):
            raise LabTLSError("TLS identity mismatch")
        ca = _read_private(path / "ca.pem")
        bundle = _read_private(path / "server.pem")
        if _CONTAINER_FILE in entries:
            _container_id(_read_private(path / _CONTAINER_FILE, 64).decode("ascii"))
        if (
            b"-----BEGIN CERTIFICATE-----" not in ca
            or b"-----BEGIN CERTIFICATE-----" not in bundle
            or b"PRIVATE KEY-----" not in bundle
        ):
            raise LabTLSError("invalid TLS material")
        return ca, bundle
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, TypeError) as exc:
        raise LabTLSError("invalid TLS directory") from exc


def _run(args):
    try:
        subprocess.run(
            args,
            check=True,
            timeout=30,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            umask=0o077,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise LabTLSError("local TLS generation failed") from exc


def prepare_tls(secrets_path: Path, task: str, name: str) -> Path:
    """Create a fresh private CA and loopback server bundle without overwriting.

    The private CA key and temporary files are discarded before returning. A
    pre-existing directory is never reused; task lifecycle must select a fresh
    secrets path and clean up only its own verified resources.
    """
    identity = _identity(task, name)
    directory = _directory(secrets_path)
    openssl = shutil.which("openssl")
    if openssl is None:
        raise LabTLSError("local TLS generation unavailable")
    try:
        os.mkdir(directory, 0o700)
    except FileExistsError as exc:
        raise LabTLSError("TLS directory already exists") from exc
    except OSError as exc:
        raise LabTLSError("cannot create TLS directory") from exc
    try:
        if not _safe_directory(directory):
            raise LabTLSError("unsafe TLS directory")
        ca_key, ca, leaf_key, csr, cert, ext = (
            directory / name
            for name in (
                "ca.key",
                "ca.pem",
                "leaf.key",
                "leaf.csr",
                "leaf.crt",
                "leaf.ext",
            )
        )
        _write_private(
            ext,
            (
                "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid,issuer\nsubjectAltName=IP:127.0.0.1,DNS:localhost,DNS:"
                + name
                + "\n"
            ).encode("ascii"),
        )
        _run(
            [
                openssl,
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-sha256",
                "-days",
                "2",
                "-subj",
                "/CN=Atlas task lab CA",
                "-addext",
                "basicConstraints=critical,CA:TRUE",
                "-addext",
                "keyUsage=critical,keyCertSign,cRLSign",
                "-keyout",
                str(ca_key),
                "-out",
                str(ca),
            ]
        )
        _run(
            [
                openssl,
                "req",
                "-new",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-sha256",
                "-subj",
                "/CN=localhost",
                "-keyout",
                str(leaf_key),
                "-out",
                str(csr),
            ]
        )
        _run(
            [
                openssl,
                "x509",
                "-req",
                "-in",
                str(csr),
                "-CA",
                str(ca),
                "-CAkey",
                str(ca_key),
                "-set_serial",
                "0x" + secrets.token_hex(16),
                "-days",
                "2",
                "-sha256",
                "-extfile",
                str(ext),
                "-out",
                str(cert),
            ]
        )
        _run([openssl, "verify", "-CAfile", str(ca), str(cert)])
        bundle = _read_private(cert) + _read_private(leaf_key) + _read_private(ca)
        _write_private(directory / "server.pem", bundle)
        for path in (ca_key, leaf_key, csr, cert, ext):
            path.unlink()
        _write_private(
            directory / "identity.json",
            json.dumps(identity, sort_keys=True, separators=(",", ":")).encode(),
        )
        _verify_directory(directory, task, name)
        return directory
    except Exception as exc:
        for filename in _SCRATCH:
            try:
                (directory / filename).unlink(missing_ok=True)
            except OSError:
                pass
        try:
            directory.rmdir()
        except OSError:
            pass
        if isinstance(exc, LabTLSError):
            raise
        raise LabTLSError("local TLS generation failed") from exc


def tls_context(
    secrets_path: Path, identity: tuple[str, str] | None = None
) -> ssl.SSLContext:
    """Return hostname-checking TLS; task identity requires its own private CA."""
    directory = _directory(secrets_path)
    if identity is None:
        if os.path.lexists(directory):
            raise LabTLSError("task TLS identity required")
        return ssl.create_default_context()
    if not isinstance(identity, tuple) or len(identity) != 2:
        raise LabTLSError("invalid task identity")
    ca, _ = _verify_directory(directory, *identity)
    try:
        # cadata uses the validated bytes rather than reopening a potentially replaced path.
        context = ssl.create_default_context(cadata=ca.decode("ascii"))
    except (UnicodeDecodeError, ssl.SSLError, ValueError) as exc:
        raise LabTLSError("invalid task CA") from exc
    if context.verify_mode != ssl.CERT_REQUIRED or not context.check_hostname:
        raise LabTLSError("TLS verification unavailable")
    return context


def server_bundle(secrets_path: Path, identity: tuple[str, str]) -> bytes:
    """Return the verified server bundle for a private Docker stdin stream."""
    if not isinstance(identity, tuple) or len(identity) != 2:
        raise LabTLSError("invalid task identity")
    return _verify_directory(_directory(secrets_path), *identity)[1]


def _container_id(value):
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value):
        raise LabTLSError("invalid task container identity")
    return value


def remember_container(
    secrets_path: Path, identity: tuple[str, str], container_id: str
) -> None:
    """Bind the task to a freshly inspected container, without replacing a prior ID."""
    if not isinstance(identity, tuple) or len(identity) != 2:
        raise LabTLSError("invalid task identity")
    container_id = _container_id(container_id)
    directory = _directory(secrets_path)
    _verify_directory(directory, *identity)
    try:
        _write_private(directory / _CONTAINER_FILE, container_id.encode("ascii"))
    except FileExistsError:
        if read_container(secrets_path, identity) != container_id:
            raise LabTLSError("task container identity changed") from None
    except OSError as exc:
        raise LabTLSError("unable to bind task container") from exc


def read_container(secrets_path: Path, identity: tuple[str, str]) -> str:
    if not isinstance(identity, tuple) or len(identity) != 2:
        raise LabTLSError("invalid task identity")
    directory = _directory(secrets_path)
    _verify_directory(directory, *identity)
    try:
        return _container_id(
            _read_private(directory / _CONTAINER_FILE, 64).decode("ascii")
        )
    except UnicodeDecodeError as exc:
        raise LabTLSError("invalid task container identity") from exc


def cleanup_tls(secrets_path: Path, task: str, name: str) -> None:
    """Remove only the exact verified task TLS files and their private directory."""
    directory = _directory(secrets_path)
    _verify_directory(directory, task, name)
    try:
        for filename in _FILES | (
            {_CONTAINER_FILE} if (directory / _CONTAINER_FILE).exists() else set()
        ):
            (directory / filename).unlink()
        directory.rmdir()
    except OSError as exc:
        raise LabTLSError("unable to clean task TLS") from exc


def tls_directory(secrets_path: Path) -> Path:
    """Validate the external private runtime location before writing credentials."""
    return _directory(secrets_path)
