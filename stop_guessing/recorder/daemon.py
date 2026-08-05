"""`cocd` — the single-writer recorder.

This is the piece the whole isolation story rested on and did not have. Until now the "recorder"
was library code running inside the agent's own process, under the agent's own uid, holding the
chain key in the agent's own environment. Every isolation claim above tier 0 was aspirational.

What a separate process buys, and why each matters:

- **Single writer.** The daemon owns the ledger exclusively, so sequence numbers and `prev_hash`
  are assigned in one place. The file lock in `sink.py` was a correct fix for concurrent writers;
  a single writer removes the concurrency instead of coordinating it.
- **Key separation.** The chain key is loaded once, at daemon start, and never enters the hook
  process. An agent that can read its own environment still cannot forge a record, because the
  key is not there to read.
- **Authoritative state.** Custody state is derived by the party that owns the history, not by the
  party being recorded.
- **Tamper resistance.** Run under a separate uid (`--isolated`) the ledger directory is not
  writable by the agent at all, which is a filesystem boundary rather than a policy one.

Deliberately small: newline-delimited JSON over a unix socket, no framework, no dependencies. A
recorder that needs a service mesh to be trustworthy will not be deployed, and one that is not
deployed records nothing.

**It fails closed on integrity and open on availability.** A daemon that cannot verify its own
chain refuses to append. A daemon that is simply absent lets the caller fall back to a direct
write, recorded honestly as `isolation_tier: 0` — never silently.
"""

from __future__ import annotations

import contextlib
import json
import os
import socket
import socketserver
import stat
import threading
from dataclasses import dataclass
from pathlib import Path

PROTOCOL = 1
SOCKET_NAME = "recorder.sock"
MAX_REQUEST = 4 * 1024 * 1024  # a single custody record; anything larger is malformed


#: AF_UNIX paths are capped by the kernel — 104 bytes on macOS, 108 on Linux — and the limit
#: counts the whole path, not the filename. A profile a few directories deep silently exceeds it
#: and `bind()` fails with "AF_UNIX path too long", which would leave the recorder never starting
#: and every record falling back to tier 0 without anyone noticing.
SOCKET_PATH_MAX = 100


def socket_path(config_dir: str | os.PathLike) -> Path:
    """The socket for this profile, shortened deterministically when the path is too long.

    The fallback lives in the user's own runtime directory at mode 0700 and is named from a digest
    of the config dir, so two profiles never collide and the path stays inside the kernel limit.
    """
    direct = Path(config_dir) / "stop-guessing" / SOCKET_NAME
    if len(str(direct)) <= SOCKET_PATH_MAX:
        return direct

    import hashlib
    import tempfile

    tag = hashlib.sha256(str(Path(config_dir).resolve()).encode()).hexdigest()[:12]
    base = Path(os.environ.get("XDG_RUNTIME_DIR") or tempfile.gettempdir())
    short = base / f"sg-{os.getuid()}" / f"{tag}.sock"
    short.parent.mkdir(parents=True, exist_ok=True)
    with contextlib.suppress(OSError):
        short.parent.chmod(0o700)
    return short


def ledger_path(config_dir: str | os.PathLike) -> Path:
    return Path(config_dir) / "stop-guessing" / "ledger" / "custody.jsonl"


@dataclass
class RecorderState:
    """Everything the daemon owns. The hook process holds none of it."""

    ledger: Path
    key: object | None
    started_at: str
    appended: int = 0
    refused: int = 0

    lock: threading.Lock = None  # type: ignore[assignment]

    def __post_init__(self):
        self.lock = threading.Lock()


#: A client that connects and never speaks used to hold a worker thread indefinitely (#45).
REQUEST_TIMEOUT = 10.0

#: Fields every recorded event must carry, at the boundary rather than in an optional builder.
#: `known_gaps` and `alterations` are required AS KEYS with `[]` meaning "nothing to report" —
#: a missing key means nobody looked, and that distinction is the whole point of the record.
REQUIRED_EVENT_FIELDS = ("op", "at", "actor")
REQUIRED_ASSERTION_KEYS = ("known_gaps", "alterations")


def _now_iso() -> str:
    from datetime import UTC, datetime

    return datetime.now(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _peer_credentials(conn) -> dict:
    """The uid/pid on the other end of the socket, when the OS will tell us.

    macOS exposes LOCAL_PEERCRED, Linux SO_PEERCRED; the struct differs, so both are attempted
    and a failure is reported as unverified rather than assumed to be us.
    """
    import struct
    import sys

    # Chosen by PLATFORM, not by try/except. Socket option 17 is SO_PEERCRED on Linux and means
    # something else entirely on macOS, where the getsockopt call SUCCEEDS and returns unrelated
    # bytes — so the first version silently reported a garbage uid as verified. A credential check
    # that can report a wrong answer confidently is worse than one that reports "unavailable".
    if sys.platform.startswith("linux"):
        try:
            buf = conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
            pid, uid, gid = struct.unpack("3i", buf)
            return {"pid": pid, "uid": uid, "gid": gid, "verified": True, "source": "SO_PEERCRED"}
        except (OSError, AttributeError, struct.error):
            pass
    elif sys.platform == "darwin" or "bsd" in sys.platform:
        # `os.getpeereid` is not present on every macOS Python build — it is missing on this one —
        # so the socket option is used directly. SOL_LOCAL/LOCAL_PEERCRED returns a `struct xucred`
        # whose first two words are the version and the peer's effective uid.
        try:
            sol_local, local_peercred = 0, 0x001
            buf = conn.getsockopt(sol_local, local_peercred, 4 + 4 + 2 + 16 * 4)
            _version, uid = struct.unpack_from("II", buf, 0)
            return {"pid": None, "uid": uid, "gid": None, "verified": True,
                    "source": "LOCAL_PEERCRED"}
        except (OSError, struct.error):
            pass
        try:
            uid, gid = os.getpeereid(conn.fileno())
            return {"pid": None, "uid": uid, "gid": gid, "verified": True,
                    "source": "getpeereid"}
        except (OSError, AttributeError):
            pass
    return {"pid": None, "uid": None, "gid": None, "verified": False, "source": "unavailable"}


def _peer_allowed(peer: dict, state) -> bool:
    """Admission. Unverifiable credentials are admitted and RECORDED as unverified.

    Refusing what cannot be verified would make the recorder unavailable on any platform whose
    peer-credential call is missing, and an unavailable recorder records nothing — which is worse
    than a recorded uncertainty. The uncertainty travels with the record instead.
    """
    if not peer.get("verified"):
        return True
    allowed = getattr(state, "allowed_uids", None)
    if allowed:
        return peer.get("uid") in allowed
    # Default: the uid running the recorder, plus root (which can reach the socket regardless).
    return peer.get("uid") in (os.getuid(), 0)


def _validate_event(event: dict) -> list[str]:
    """Every missing requirement, not just the first — see CustodyRecord's own rule."""
    problems = [f"missing {f}" for f in REQUIRED_EVENT_FIELDS if not event.get(f)]
    problems += [f"missing {k} (use [] to assert there is nothing to report; a missing key "
                 f"means nobody looked)"
                 for k in REQUIRED_ASSERTION_KEYS if k not in event]
    for k in REQUIRED_ASSERTION_KEYS:
        if k in event and not isinstance(event[k], list):
            problems.append(f"{k} must be a list, got {type(event[k]).__name__}")
    return problems


class _Handler(socketserver.StreamRequestHandler):
    """One request, one response, newline-delimited JSON."""

    state: RecorderState = None  # type: ignore[assignment]

    def handle(self) -> None:
        # #43/#45 (SG-HARD-010/032). Two things this did not do: it never asked WHO was
        # connecting, and it had no deadline. The socket is mode 0600, so the filesystem already
        # bounds callers to this uid — but "the filesystem probably handles it" is an assumption,
        # and an assumption is what this project exists to replace with a check. Peer credentials
        # are read and recorded, so every appended record can name the process that asked.
        peer = _peer_credentials(self.connection)
        if not _peer_allowed(peer, self.state):
            self._reply({"ok": False, "refused": True,
                         "error": f"peer uid {peer.get('uid')} is not admitted by this recorder "
                                  f"(serving uid {os.getuid()})"})
            return
        self.peer = peer
        try:
            self.connection.settimeout(REQUEST_TIMEOUT)
            raw = self.rfile.readline(MAX_REQUEST)
        except (TimeoutError, OSError, ValueError):
            # A client that opens a connection and never speaks used to hold a thread forever.
            return
        if not raw:
            return
        try:
            req = json.loads(raw)
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            self._reply({"ok": False, "error": f"malformed request: {exc}"})
            return
        try:
            self._reply(self.dispatch(req))
        except Exception as exc:  # noqa: BLE001 - one bad request must not kill the recorder
            self._reply({"ok": False, "error": f"{type(exc).__name__}: {exc}"})

    def _reply(self, payload: dict) -> None:
        try:
            self.wfile.write((json.dumps(payload) + "\n").encode())
            self.wfile.flush()
        except OSError:
            pass

    # ── operations ──────────────────────────────────────────────────────────

    def dispatch(self, req: dict) -> dict:
        op = req.get("op")
        if op == "ping":
            return {"ok": True, "protocol": PROTOCOL, "pid": os.getpid(),
                    "uid": os.getuid(), "appended": self.state.appended,
                    "refused": self.state.refused, "started_at": self.state.started_at,
                    "keyed": self.state.key is not None}
        if op == "append":
            return self.op_append(req)
        if op == "verify":
            return self.op_verify()
        if op == "state":
            return self.op_state(req)
        return {"ok": False, "error": f"unknown op {op!r}"}

    def op_append(self, req: dict) -> dict:
        from stop_guessing.ledger.sink import LedgerError, record

        event = req.get("event")
        if not isinstance(event, dict):
            return {"ok": False, "error": "event must be an object"}
        # The caller does not get to choose these. A recorded party that could set its own
        # sequence or predecessor could insert itself anywhere in history.
        for reserved in ("seq", "prev_hash", "hash", "hash_alg", "keyid"):
            event.pop(reserved, None)

        # #44 (SG-HARD-011). The Tier-A schema gate only ran when a caller CHOSE to build its
        # event through CustodyRecord.build(); the sink and this daemon accepted any dict at all,
        # including {"op": ..., "at": ..., "actor": ...}. So the claim that the recorder refuses
        # structurally incomplete records described a builder helper, not the recorder. Validation
        # now happens here, at the boundary the agent actually reaches.
        problems = _validate_event(event)
        if problems:
            self.state.refused += 1
            return {"ok": False, "refused": True,
                    "error": "record refused at the recorder boundary: " + "; ".join(problems)}

        # The recorder stamps who asked. A caller-supplied actor is corroboration, not evidence.
        peer = getattr(self, "peer", {}) or {}
        event.setdefault("recorded_at", _now_iso())
        event["peer"] = {"uid": peer.get("uid"), "pid": peer.get("pid"),
                         "verified": peer.get("verified", False)}

        with self.state.lock:
            try:
                entry = record(self.state.ledger, event, self.state.key)
            except LedgerError as exc:
                self.state.refused += 1
                return {"ok": False, "error": str(exc), "refused": True}
            self.state.appended += 1
        return {"ok": True, "ref": f"sg:{entry['seq']}:{entry['hash'][:16]}",
                "seq": entry["seq"], "hash": entry["hash"]}

    def op_verify(self) -> dict:
        from stop_guessing.ledger.sink import load

        with self.state.lock:
            loaded = load(self.state.ledger, self.state.key)
        return {"ok": True, "chain": loaded.chain.to_dict(),
                "records": len(loaded.entries), "truncated": loaded.truncated}

    def op_state(self, req: dict) -> dict:
        """Custody state derived by the party that owns the history."""
        from stop_guessing.ledger.sink import load
        from stop_guessing.taint.state import rebuild

        session = req.get("session_id")
        if not isinstance(session, str):
            return {"ok": False, "error": "session_id must be a string"}
        with self.state.lock:
            loaded = load(self.state.ledger, self.state.key)
        if not loaded.chain.intact:
            return {"ok": False, "error": "chain is broken; state derived from it is worthless",
                    "chain": loaded.chain.to_dict()}
        st = rebuild(loaded.entries, session)
        return {"ok": True, "digest": st.digest, "labels": sorted(st.labels),
                "depth": st.depth, "touched": st.touched,
                "sources": {k: v.to_dict() for k, v in st.sources.items()},
                "since_last_egress": st.since_last_egress}


class _Server(socketserver.ThreadingUnixStreamServer):
    daemon_threads = True
    allow_reuse_address = True

    #: socketserver defaults this to 5. With a dozen concurrent hooks the kernel refuses the
    #: overflow, the client reads that as "no daemon", and the record is LOST — under concurrency,
    #: silently. A recorder that drops evidence when busy is worse than one that is slow.
    request_queue_size = 256

    def __init__(self, path: str, handler):
        super().__init__(path, handler)


def serve(config_dir: str | os.PathLike, *, key=None, ready=None) -> _Server:
    """Bind the socket and serve. Returns the server; the caller runs or closes it.

    The socket is created 0660 so a separate-uid daemon can still be reached by the agent's group
    without the agent being able to touch the ledger directory itself. That asymmetry is the whole
    point: the agent may ask the recorder to record, and may not write the record.
    """
    cfg = Path(config_dir)
    sock = socket_path(cfg)
    sock.parent.mkdir(parents=True, exist_ok=True)
    led = ledger_path(cfg)
    led.parent.mkdir(parents=True, exist_ok=True)

    if sock.exists():
        # A stale socket from a killed daemon would otherwise make bind() fail forever.
        if _ping(sock) is None:
            sock.unlink()
        else:
            raise OSError(f"a recorder is already listening on {sock}")

    from datetime import UTC, datetime

    state = RecorderState(
        ledger=led, key=key,
        started_at=datetime.now(UTC).isoformat(timespec="seconds").replace("+00:00", "Z"),
    )
    handler = type("Handler", (_Handler,), {"state": state})
    server = _Server(str(sock), handler)
    os.chmod(sock, stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP | stat.S_IWGRP)
    if ready is not None:
        ready.set()
    return server


def _ping(sock: Path, timeout: float = 1.0) -> dict | None:
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect(str(sock))
            s.sendall(b'{"op":"ping"}\n')
            data = s.makefile("rb").readline(65536)
        return json.loads(data) if data else None
    except (OSError, ValueError):
        return None


def is_running(config_dir: str | os.PathLike) -> dict | None:
    """The daemon's own report, or None. Used by `doctor` and by the isolation tier."""
    return _ping(socket_path(config_dir))


def main(argv: list[str] | None = None) -> int:
    import argparse

    ap = argparse.ArgumentParser(prog="cocd", description="STOP-GUESSING single-writer recorder")
    ap.add_argument("--config-dir", default=os.environ.get("CLAUDE_CONFIG_DIR")
                    or os.path.expanduser("~/.claude"))
    ap.add_argument("--keyfile", help="chain key file (mode 600); the hook never sees it")
    ap.add_argument("--foreground", action="store_true")
    args = ap.parse_args(argv)

    key = None
    if args.keyfile:
        from stop_guessing.attest.keys import from_keyfile

        got = from_keyfile(args.keyfile)
        key = got[0] if got else None
    else:
        from stop_guessing.attest.keys import from_env

        got = from_env()
        key = got[0] if got else None

    if key is None:
        print("REFUSED: the recorder will not run unkeyed. Records it wrote could be forged by "
              "the party it records, which is the one thing it exists to prevent.")
        return 2

    server = serve(args.config_dir, key=key)
    print(f"cocd listening on {socket_path(args.config_dir)} as uid {os.getuid()}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        socket_path(args.config_dir).unlink(missing_ok=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
