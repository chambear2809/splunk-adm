"""Sanitized operator log for refused and failed app requests.

Each event is one key=value line in $SPLUNK_HOME/var/log/splunk/splunk_adm.log.
Every value is a closed vocabulary, a validated identifier, or a number. Request
and response bodies, headers, session data, principals and exception messages
are never written. Logging is best effort: no failure here reaches the caller.
"""

import configparser
import logging
import logging.handlers
import os
from pathlib import Path
import re
import stat
import threading
import time
import uuid

LOG_NAME = "splunk_adm.log"
MAX_BYTES = 5 * 1024 * 1024
BACKUP_COUNT = 3
RETRY_SECONDS = 60.0
CONFIG_SECONDS = 30.0
DEFAULT_LEVEL = "INFO"
LEVELS = {
    "DEBUG": logging.DEBUG,
    "INFO": logging.INFO,
    "WARNING": logging.WARNING,
    "ERROR": logging.ERROR,
    "OFF": logging.CRITICAL + 10,
}
APP_ROOT = Path(__file__).resolve().parents[2]

_IDENTIFIER = re.compile(r"[a-z][a-z0-9_.:-]{0,63}")
_CLASS_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,63}")
_UUID = re.compile(
    r"[0-9a-f]{8}-?[0-9a-f]{4}-?[0-9a-f]{4}-?[0-9a-f]{4}-?[0-9a-f]{12}", re.I
)
_METHODS = frozenset({"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"})
_CORRELATION_HEADERS = frozenset({"x-request-id", "x-correlation-id"})

_lock = threading.Lock()
_logger = None
_retry_after = 0.0
_level = (0.0, LEVELS[DEFAULT_LEVEL])


class _UtcFormatter(logging.Formatter):
    converter = time.gmtime
    default_time_format = "%Y-%m-%dT%H:%M:%S"
    default_msec_format = "%s.%03dZ"


class _SafeRotatingHandler(logging.handlers.RotatingFileHandler):
    """Size-bounded handler that never follows a link and tolerates peers.

    Several persistent handler processes append to the same file. Size is read
    from the file itself and a stream whose path was rotated by a peer is
    reopened, so rotation bounds hold across processes.
    """

    def _open(self):
        flags = (
            os.O_WRONLY
            | os.O_APPEND
            | os.O_CREAT
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0)
        )
        descriptor = os.open(self.baseFilename, flags, 0o600)
        try:
            info = os.fstat(descriptor)
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise OSError("operator log is not a private regular file")
            return os.fdopen(descriptor, "a", encoding="utf-8")
        except BaseException:
            os.close(descriptor)
            raise

    def _replaced(self):
        try:
            current = os.stat(self.baseFilename, follow_symlinks=False)
        except FileNotFoundError:
            return True
        opened = os.fstat(self.stream.fileno())
        return (current.st_dev, current.st_ino) != (opened.st_dev, opened.st_ino)

    def shouldRollover(self, record):
        if self.stream is None:
            self.stream = self._open()
        self.stream.flush()
        size = os.fstat(self.stream.fileno()).st_size
        line = len(self.format(record).encode("utf-8")) + 1
        return size > 0 and size + line > self.maxBytes

    def emit(self, record):
        try:
            if self.stream is not None and self._replaced():
                self.stream.close()
                self.stream = None
            if self.shouldRollover(record):
                self.doRollover()
            logging.FileHandler.emit(self, record)
        except Exception:
            self.handleError(record)

    def handleError(self, record):
        # Stay silent: the default handler prints the record and a traceback.
        if self.stream is not None:
            try:
                self.stream.close()
            except Exception:
                pass
            self.stream = None


def log_path():
    """Return the operator log path, or None unless SPLUNK_HOME is canonical."""
    home = os.environ.get("SPLUNK_HOME", "")
    if not home or "\x00" in home:
        return None
    root = Path(home)
    if not root.is_absolute():
        return None
    try:
        if root.resolve(strict=True) != root:
            return None
        directory = root / "var" / "log" / "splunk"
        if directory.resolve(strict=True) != directory:
            return None
        if not stat.S_ISDIR(directory.lstat().st_mode):
            return None
    except (OSError, RuntimeError, ValueError):
        return None
    return directory / LOG_NAME


def _threshold():
    global _level
    expires, value = _level
    now = time.monotonic()
    if now < expires:
        return value
    name = DEFAULT_LEVEL
    parser = configparser.RawConfigParser()
    try:
        parser.read(
            [
                APP_ROOT / "default/adm_logging.conf",
                APP_ROOT / "local/adm_logging.conf",
            ],
            encoding="utf-8",
        )
        name = parser.get("logging", "level", fallback=DEFAULT_LEVEL).strip().upper()
    except (configparser.Error, OSError, UnicodeError, ValueError):
        name = DEFAULT_LEVEL
    value = LEVELS.get(name, LEVELS[DEFAULT_LEVEL])
    _level = (now + CONFIG_SECONDS, value)
    return value


def _get_logger():
    global _logger, _retry_after
    if _logger is not None:
        return _logger
    with _lock:
        if _logger is not None:
            return _logger
        now = time.monotonic()
        if now < _retry_after:
            return None
        path = log_path()
        if path is None:
            _retry_after = now + RETRY_SECONDS
            return None
        handler = _SafeRotatingHandler(
            str(path),
            maxBytes=MAX_BYTES,
            backupCount=BACKUP_COUNT,
            encoding="utf-8",
            delay=True,
        )
        handler.setFormatter(
            _UtcFormatter("%(asctime)s level=%(levelname)s %(message)s")
        )
        # Unregistered logger: Splunk or library logging configuration cannot
        # attach handlers to it or propagate its records elsewhere.
        logger = logging.Logger("splunk_adm.operator", logging.DEBUG)
        logger.propagate = False
        logger.addHandler(handler)
        _logger = logger
        return logger


def _identifier(value):
    if isinstance(value, str) and _IDENTIFIER.fullmatch(value):
        return value
    return None


def _headers(request):
    headers = request.get("headers")
    if isinstance(headers, dict):
        return headers.items()
    if isinstance(headers, list):
        return [
            item
            for item in headers
            if isinstance(item, (list, tuple)) and len(item) == 2
        ]
    return ()


def correlation_id(request=None):
    """Return a client UUID request id when supplied, otherwise a fresh one."""
    if isinstance(request, dict):
        for name, value in _headers(request):
            if (
                isinstance(name, str)
                and name.lower() in _CORRELATION_HEADERS
                and isinstance(value, str)
                and _UUID.fullmatch(value)
            ):
                return value.replace("-", "").lower()
    return uuid.uuid4().hex


def _outcome(status, exit_code):
    if isinstance(status, int):
        return "ok" if status < 400 else "refused" if status < 500 else "failed"
    return "ok" if exit_code == 0 else "failed"


def log_outcome(
    handler,
    *,
    started,
    status=None,
    code=None,
    outcome=None,
    error=None,
    request=None,
    exit_code=None,
):
    """Write one sanitized outcome line. Never raises and never blocks the caller."""
    try:
        if type(status) is not int or not 100 <= status <= 599:
            status = None
        if type(exit_code) is not int or not 0 <= exit_code <= 255:
            exit_code = None
        outcome = outcome if outcome in ("ok", "refused", "failed") else None
        outcome = outcome or _outcome(status, exit_code)
        level = {"ok": logging.DEBUG, "refused": logging.INFO}.get(
            outcome, logging.ERROR
        )
        if level < _threshold():
            return
        logger = _get_logger()
        if logger is None:
            return
        method = request.get("method") if isinstance(request, dict) else None
        error_class = type(error).__name__ if error is not None else None
        fields = [
            ("event", "adm_request"),
            ("outcome", outcome),
            ("handler", _identifier(handler) or "unknown"),
            ("method", method if method in _METHODS else None),
            ("status", status),
            ("exit_code", exit_code),
            (
                "code",
                _identifier(code) or ("unspecified" if code is not None else None),
            ),
            (
                "error_class",
                error_class
                if error_class and _CLASS_NAME.fullmatch(error_class)
                else None,
            ),
            ("correlation_id", correlation_id(request)),
            ("duration_ms", max(0, int((time.monotonic() - started) * 1000))),
        ]
        logger.log(
            level,
            " ".join(f"{key}={value}" for key, value in fields if value is not None),
        )
    except Exception:
        pass


def log_response(handler, response, *, started, request=None, error=None):
    """Log a persistent-handler response and return it unchanged."""
    try:
        status = response.get("status") if isinstance(response, dict) else None
        payload = response.get("payload") if isinstance(response, dict) else None
        code = None
        if isinstance(payload, dict):
            code = next(
                (
                    payload[key]
                    for key in ("code", "error")
                    if _identifier(payload.get(key))
                ),
                payload.get("code", payload.get("error")),
            )
        log_outcome(
            handler,
            started=started,
            status=status,
            code=code,
            error=error,
            request=request,
        )
    except Exception:
        pass
    return response


def _reset_for_tests():
    global _logger, _retry_after, _level
    with _lock:
        if _logger is not None:
            for handler in list(_logger.handlers):
                handler.close()
        _logger = None
        _retry_after = 0.0
        _level = (0.0, LEVELS[DEFAULT_LEVEL])
