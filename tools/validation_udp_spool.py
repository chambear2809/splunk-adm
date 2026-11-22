#!/usr/bin/env python3
"""Bounded IPv4 UDP maintenance spool; defaults to a non-mutating dry run.

UDP has no delivery acknowledgement: sent is not indexed. Kernel/socket overflow,
process outages, disk failure, source-side loss and cutover gaps can lose packets.
Replay may duplicate data, reorder across interrupted retries, and arrive too late
for NetFlow/IPFIX templates, sequence state, conntrack or time windows. Preserve
exporter identity only with explicitly enabled Linux IP_TRANSPARENT and the needed
routing/firewall configuration; this tool never changes routing or firewall rules.
Do not claim end-to-end losslessness. The SQLite limit bounds database and single
transaction WAL allocations, not filesystem metadata, other files or kernel memory.
Destination identity is observed after NAT: IP_PKTINFO and the bound port do not
recover an original pre-NAT address or port. Performance is not yet measured.
"""

import argparse
import contextlib
import fcntl
import ipaddress
import json
import os
from pathlib import Path
import socket
import sqlite3
import struct
import sys
import time

IP_PKTINFO = getattr(socket, "IP_PKTINFO", 8)
IP_TRANSPARENT = getattr(socket, "IP_TRANSPARENT", 19)
SO_RXQ_OVFL = getattr(socket, "SO_RXQ_OVFL", 40)
MAX_PACKET = 65507
MIN_STORAGE = 4 * 1024 * 1024


def endpoint(value):
    try:
        host, port = value.rsplit(":", 1)
        addr = ipaddress.IPv4Address(host)
        number = int(port)
        if not 1 <= number <= 65535:
            raise ValueError
        return str(addr), number
    except (ValueError, AttributeError) as exc:
        raise argparse.ArgumentTypeError("expected IPv4:port, port 1–65535") from exc


def positive(value):
    try:
        n = int(value)
        if n <= 0:
            raise ValueError
        return n
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be a positive integer") from exc


def secure_dir(path):
    path = Path(path)
    info = path.lstat()
    if not path.is_dir() or path.is_symlink() or info.st_uid != os.geteuid():
        raise ValueError("spool directory must be an owned, non-symlink directory")
    if info.st_mode & 0o077:
        raise ValueError("spool directory must have mode 0700 or stricter")
    return path


class Spool:
    def __init__(self, directory, max_storage, max_queue_bytes, max_records):
        os.umask(0o077)
        self.directory = secure_dir(directory)
        self.max_queue_bytes, self.max_records = max_queue_bytes, max_records
        if max_storage < MIN_STORAGE:
            raise ValueError("storage limit must be at least 4 MiB")
        self.path = self.directory / "udp-spool.sqlite3"
        for suffix in ("", "-wal", "-shm"):
            path = Path(str(self.path) + suffix)
            if path.exists() or path.is_symlink():
                info = path.lstat()
                if (
                    not path.is_file()
                    or path.is_symlink()
                    or info.st_uid != os.geteuid()
                    or info.st_nlink != 1
                    or info.st_mode & 0o077
                ):
                    raise ValueError(
                        "spool files must be owned regular files with mode 0600 or stricter"
                    )
        lock = self.directory / "udp-spool.lock"
        fd = os.open(lock, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        self.lock = os.fdopen(fd, "r+")
        try:
            info = os.fstat(fd)
            if (
                info.st_uid != os.geteuid()
                or info.st_nlink != 1
                or info.st_mode & 0o077
            ):
                raise ValueError("spool lock must be owned, private and single-linked")
            fcntl.flock(self.lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.db = sqlite3.connect(self.path)
            self.db.execute("PRAGMA page_size=4096")
            if self.db.execute("PRAGMA page_size").fetchone()[0] != 4096:
                raise ValueError("existing database page size is unsupported")
            # One transaction may write at most one full DB's worth to WAL. The
            # remainder reserves WAL headers, SHM and the small lock file.
            pages = (max_storage - 131072) // 8256
            actual_pages = self.db.execute(f"PRAGMA max_page_count={pages}").fetchone()[
                0
            ]
            if actual_pages > pages:
                raise ValueError("existing database exceeds requested storage limit")
            self.db.execute("PRAGMA journal_mode=WAL")
            self.db.execute("PRAGMA synchronous=FULL")
            version = self.db.execute("PRAGMA user_version").fetchone()[0]
            if version not in (0, 1):
                raise ValueError("unsupported spool schema")
            if (
                version == 0
                and self.db.execute(
                    "SELECT name FROM sqlite_master WHERE type='table' AND name='packets'"
                ).fetchone()
            ):
                raise ValueError("legacy spool schema requires manual migration")
            self.db.executescript("""
                CREATE TABLE IF NOT EXISTS packets (
                    seq INTEGER PRIMARY KEY AUTOINCREMENT, observed_ns INTEGER NOT NULL,
                    source_ip TEXT NOT NULL, source_port INTEGER NOT NULL,
                    observed_destination_ip TEXT NOT NULL, observed_destination_port INTEGER NOT NULL,
                    payload BLOB NOT NULL, sent_ns INTEGER);
                CREATE TABLE IF NOT EXISTS counters (name TEXT PRIMARY KEY, value INTEGER NOT NULL);
                CREATE TABLE IF NOT EXISTS queue_state (id INTEGER PRIMARY KEY CHECK(id=1), queued INTEGER NOT NULL, bytes INTEGER NOT NULL);
                INSERT OR IGNORE INTO queue_state VALUES (1,0,0);
                CREATE INDEX IF NOT EXISTS packets_pending ON packets(seq) WHERE sent_ns IS NULL;
                PRAGMA user_version=1;
            """)
            self.db.commit()
            self.checkpoint()
        except Exception:
            self.lock.close()
            raise

    def checkpoint(self):
        result = self.db.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()
        if result[0] != 0:
            raise RuntimeError("WAL checkpoint blocked; stop to preserve storage bound")

    def increment(self, name, amount=1):
        self.db.execute(
            "INSERT INTO counters VALUES (?,?) ON CONFLICT(name) DO UPDATE SET value=value+excluded.value",
            (name, amount),
        )

    def record(self, payload, source, destination, observed_ns):
        count, used = self.db.execute(
            "SELECT queued, bytes FROM queue_state WHERE id=1"
        ).fetchone()
        if count >= self.max_records or used + len(payload) > self.max_queue_bytes:
            with self.db:
                self.increment("queue_overflow")
            self.checkpoint()
            return False
        with self.db:
            self.db.execute(
                "INSERT INTO packets(observed_ns,source_ip,source_port,observed_destination_ip,observed_destination_port,payload) VALUES(?,?,?,?,?,?)",
                (
                    observed_ns,
                    source[0],
                    source[1],
                    destination[0],
                    destination[1],
                    payload,
                ),
            )
            self.db.execute(
                "UPDATE queue_state SET queued=queued+1, bytes=bytes+? WHERE id=1",
                (len(payload),),
            )
            self.increment("captured")
        self.checkpoint()
        return True

    def report(self):
        return read_report(self.db)

    def close(self):
        self.db.close()
        self.lock.close()


def replay(spool, destination, transparent=False, socket_factory=socket.socket):
    sent = 0
    while True:
        row = spool.db.execute(
            "SELECT seq,source_ip,source_port,payload FROM packets WHERE sent_ns IS NULL ORDER BY seq LIMIT 1"
        ).fetchone()
        if row is None:
            break
        seq, source_ip, source_port, payload = row
        with contextlib.closing(
            socket_factory(socket.AF_INET, socket.SOCK_DGRAM)
        ) as sock:
            if transparent:
                sock.setsockopt(socket.SOL_IP, IP_TRANSPARENT, 1)
                sock.bind((source_ip, source_port))
            written = sock.sendto(payload, destination)
            if written != len(payload):
                raise OSError("partial UDP send; record remains queued")
        # A crash here can duplicate on restart; never claim indexed delivery.
        with spool.db:
            spool.db.execute(
                "UPDATE packets SET sent_ns=? WHERE seq=? AND sent_ns IS NULL",
                (time.time_ns(), seq),
            )
            spool.db.execute(
                "UPDATE queue_state SET queued=queued-1, bytes=bytes-? WHERE id=1",
                (len(payload),),
            )
            spool.increment("sent")
        spool.checkpoint()
        sent += 1
    return sent


def capture(spool, listen, max_payload):
    with contextlib.closing(socket.socket(socket.AF_INET, socket.SOCK_DGRAM)) as sock:
        sock.setsockopt(socket.SOL_IP, IP_PKTINFO, 1)
        try:
            sock.setsockopt(socket.SOL_SOCKET, SO_RXQ_OVFL, 1)
            overflow_supported = True
        except OSError:
            overflow_supported = False
        sock.bind(listen)
        print(
            json.dumps(
                {"listening": listen, "kernel_drop_counter_enabled": overflow_supported}
            ),
            flush=True,
        )
        last_overflow = 0
        while True:
            payload, ancillary, flags, source = sock.recvmsg(max_payload, 128)
            observed_ns = time.time_ns()
            destination_ip = None
            for level, kind, data in ancillary:
                if level == socket.SOL_IP and kind == IP_PKTINFO and len(data) >= 12:
                    destination_ip = socket.inet_ntoa(data[8:12])
                if (
                    level == socket.SOL_SOCKET
                    and kind == SO_RXQ_OVFL
                    and len(data) >= 4
                ):
                    current = struct.unpack("=I", data[:4])[0]
                    delta = (current - last_overflow) % (2**32)
                    with spool.db:
                        spool.increment("kernel_overflow_reported", delta)
                    last_overflow = current
                    if delta:
                        spool.checkpoint()
                        raise CaptureLoss("kernel receive queue overflow detected")
            if flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC) or destination_ip is None:
                with spool.db:
                    spool.increment("truncated_or_missing_destination")
                spool.checkpoint()
                raise CaptureLoss(
                    "discarded truncated packet or missing destination metadata"
                )
            if not spool.record(
                payload, source, (destination_ip, listen[1]), observed_ns
            ):
                raise CaptureLoss("queue overflow: datagram dropped")


class CaptureLoss(RuntimeError):
    pass


def read_report(db):
    counts = dict(db.execute("SELECT name,value FROM counters"))
    queued, size = db.execute(
        "SELECT queued,bytes FROM queue_state WHERE id=1"
    ).fetchone()
    return {
        "counters": counts,
        "queued": queued,
        "queued_payload_bytes": size,
        "indexed_delivery": "unknown",
    }


def readonly_status(directory):
    directory = secure_dir(directory)
    path = directory / "udp-spool.sqlite3"
    for suffix in ("", "-wal", "-shm"):
        candidate = Path(str(path) + suffix)
        if suffix == "" or candidate.exists() or candidate.is_symlink():
            info = candidate.lstat()
            if (
                candidate.is_symlink()
                or not candidate.is_file()
                or info.st_uid != os.geteuid()
                or info.st_nlink != 1
                or info.st_mode & 0o077
            ):
                raise ValueError("unsafe spool file")
    wal = Path(str(path) + "-wal")
    shm = Path(str(path) + "-shm")
    if wal.exists() and not shm.exists():
        raise ValueError("read-only status refuses WAL without existing shared memory")
    with contextlib.closing(
        sqlite3.connect(path.resolve().as_uri() + "?mode=ro", uri=True)
    ) as db:
        if db.execute("PRAGMA user_version").fetchone()[0] != 1:
            raise ValueError("unsupported spool schema")
        return read_report(db)


def parser():
    p = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    p.add_argument("mode", choices=("capture", "replay", "status"))
    p.add_argument("--spool-dir", required=True, type=Path)
    p.add_argument("--max-storage-bytes", type=positive, default=1024 * 1024 * 1024)
    p.add_argument("--max-queue-bytes", type=positive, default=256 * 1024 * 1024)
    p.add_argument("--max-records", type=positive, default=1000000)
    p.add_argument("--max-payload", type=positive, default=MAX_PACKET)
    p.add_argument("--listen", type=endpoint)
    p.add_argument("--destination", type=endpoint)
    p.add_argument("--allow-destination", type=endpoint, action="append", default=[])
    p.add_argument("--ack-duplicate-risk", action="store_true")
    p.add_argument("--transparent-source", action="store_true")
    p.add_argument(
        "--apply",
        action="store_true",
        help="perform capture or replay; otherwise dry run",
    )
    return p


def main(argv=None):
    p = parser()
    args = p.parse_args(argv)
    if (
        args.max_storage_bytes < MIN_STORAGE
        or args.max_payload > MAX_PACKET
        or args.max_queue_bytes > ((args.max_storage_bytes - 131072) // 8256) * 4096
    ):
        p.error("invalid storage, queue or payload limit")
    if args.mode == "capture" and (
        not args.listen
        or args.destination
        or args.allow_destination
        or args.transparent_source
        or args.ack_duplicate_risk
    ):
        p.error("capture requires --listen and no replay options")
    if args.mode == "replay" and (
        not args.destination
        or args.listen
        or args.destination not in args.allow_destination
    ):
        p.error("replay requires --destination included in --allow-destination")
    if (
        args.mode == "replay"
        and args.destination
        and (
            ipaddress.IPv4Address(args.destination[0]).is_multicast
            or ipaddress.IPv4Address(args.destination[0]).is_unspecified
            or args.destination[0] == "255.255.255.255"
        )
    ):
        p.error("replay destination must be a unicast address")
    if args.mode == "replay" and args.apply and not args.ack_duplicate_risk:
        p.error("replay requires --ack-duplicate-risk")
    if (
        args.mode == "replay"
        and args.apply
        and args.transparent_source
        and (sys.platform != "linux" or os.geteuid() != 0)
    ):
        p.error("transparent source replay requires Linux and root")
    if args.mode == "status" and (
        args.listen
        or args.destination
        or args.allow_destination
        or args.transparent_source
        or args.ack_duplicate_risk
    ):
        p.error("status does not accept capture or replay options")
    if args.mode == "status":
        print(json.dumps(readonly_status(args.spool_dir)))
        return 0
    if not args.apply:
        print(
            json.dumps(
                {
                    "mode": args.mode,
                    "dry_run": True,
                    "spool_dir": str(args.spool_dir.absolute()),
                    "listen": args.listen,
                    "destination": args.destination,
                    "allow_destination": args.allow_destination,
                    "max_storage_bytes": args.max_storage_bytes,
                    "max_queue_bytes": args.max_queue_bytes,
                    "max_records": args.max_records,
                    "max_payload": args.max_payload,
                    "transparent_source": args.transparent_source,
                    "ack_duplicate_risk": args.ack_duplicate_risk,
                    "indexed_delivery": "unknown",
                    "warnings": [
                        "UDP loss and replay duplicates are possible",
                        "observed destination is post-NAT",
                        "transparent source requires routing and root",
                        "performance not measured",
                    ],
                }
            )
        )
        return 0
    if sys.platform != "linux" and args.mode == "capture":
        p.error("capture requires Linux IP_PKTINFO")
    os.umask(0o077)
    spool = Spool(
        args.spool_dir, args.max_storage_bytes, args.max_queue_bytes, args.max_records
    )
    try:
        if args.mode == "capture":
            capture(spool, args.listen, args.max_payload)
        elif args.mode == "replay":
            replay(spool, args.destination, args.transparent_source)
        print(json.dumps(spool.report()))
    except KeyboardInterrupt:
        print(json.dumps({"outcome": "interrupted", **spool.report()}))
        return 130
    except (CaptureLoss, sqlite3.Error, OSError, RuntimeError):
        try:
            print(json.dumps({"outcome": "failed", **spool.report()}), file=sys.stderr)
        except sqlite3.Error:
            print("capture/replay failed; report unavailable", file=sys.stderr)
        raise
    finally:
        spool.close()
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, sqlite3.Error, RuntimeError) as exc:
        print(f"spool stopped: {exc}", file=sys.stderr)
        raise SystemExit(1)
