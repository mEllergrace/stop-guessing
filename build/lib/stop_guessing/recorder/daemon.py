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


class _Handler(socketserver.StreamRequestHandler):
    """One request, one response, newline-delimited JSON."""

    state: RecorderState = None  # type: ignore[assignment]

    def handle(self) -> None:
        try:
            raw = self.rfile.readline(MAX_REQUEST)
        except (OSError, ValueError):
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
