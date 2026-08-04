"""Talk to the recorder, and be honest when it is not there.

The hook process holds no chain key and owns no ledger when a daemon is running — it asks. When
no daemon is running it falls back to a direct write, and the record says so: `isolation_tier: 0`
with the reason. Availability degrades; honesty does not.

The tier is derived from what is actually true at the moment of writing, never asserted:

    0  in-process write, same uid as the agent, key in the agent's environment
    1  daemon on the same uid — key separation, single writer, but the agent could kill it
    2  daemon under a different uid — the ledger is not writable by the agent at all
    3  remote recorder (not implemented; reserved rather than claimed)
"""

from __future__ import annotations

import json
import os
import socket
import time
from dataclasses import dataclass
from pathlib import Path

from stop_guessing.recorder.daemon import socket_path

TIMEOUT = 5.0


@dataclass(frozen=True)
class Appended:
    ref: str | None
    isolation_tier: int
    via: str
    error: str | None = None

    def to_dict(self) -> dict:
        return {"ref": self.ref, "isolation_tier": self.isolation_tier,
                "via": self.via, "error": self.error}


#: A refused connection under load is a full accept queue, not an absent daemon. Treating the two
#: alike lost records silently when several hooks ran at once — 57 of 60 in the first concurrency
#: test. Retry briefly before concluding the recorder is gone.
CONNECT_RETRIES = 6
RETRY_BACKOFF = 0.05


def _request(cfg: Path, payload: dict, timeout: float = TIMEOUT) -> dict | None:
    sock = socket_path(cfg)
    if not sock.exists():
        return None
    blob = (json.dumps(payload) + "\n").encode()
    for attempt in range(CONNECT_RETRIES):
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                s.connect(str(sock))
                s.sendall(blob)
                line = s.makefile("rb").readline(4 * 1024 * 1024)
            return json.loads(line) if line else None
        except ConnectionRefusedError:
            # Accept queue full. The daemon is there; it is busy.
            time.sleep(RETRY_BACKOFF * (attempt + 1))
        except (OSError, ValueError):
            return None
    return None


def daemon_info(config_dir: str | os.PathLike) -> dict | None:
    return _request(Path(config_dir), {"op": "ping"}, timeout=1.0)


def isolation_tier(config_dir: str | os.PathLike) -> tuple[int, str]:
    """The tier that is true right now, with the reason. Never an assertion."""
    info = daemon_info(config_dir)
    if info is None or not info.get("ok"):
        return 0, "no recorder daemon; writing in-process under the agent's own uid"
    if info.get("uid") != os.getuid():
        return 2, f"recorder runs as uid {info['uid']}, agent as {os.getuid()}"
    return 1, "recorder is a separate process on the same uid"


def append(config_dir: str | os.PathLike, event: dict, *, fallback_key=None) -> Appended:
    """Ask the recorder to append. Falls back to a direct write, recorded as tier 0."""
    cfg = Path(config_dir)
    tier, why = isolation_tier(cfg)

    if tier > 0:
        resp = _request(cfg, {"op": "append", "event": event})
        if resp is not None and resp.get("ok"):
            return Appended(resp["ref"], tier, "daemon")
        if resp is not None and resp.get("refused"):
            # The daemon refused on integrity. Falling back would launder that refusal.
            return Appended(None, tier, "daemon", resp.get("error"))
        return _direct(cfg, event, fallback_key,
                       f"daemon unreachable mid-request ({why}); wrote in-process")

    return _direct(cfg, event, fallback_key, why)


def _direct(cfg: Path, event: dict, key, why: str) -> Appended:
    from stop_guessing.ledger.sink import LedgerError, record
    from stop_guessing.recorder.daemon import ledger_path

    event = dict(event)
    gaps = list(event.get("known_gaps") or [])
    gaps.append(f"isolation tier 0: {why}")
    event["known_gaps"] = gaps
    try:
        entry = record(ledger_path(cfg), event, key)
    except LedgerError as exc:
        return Appended(None, 0, "in-process", str(exc))
    return Appended(f"sg:{entry['seq']}:{entry['hash'][:16]}", 0, "in-process")


def custody_state(config_dir: str | os.PathLike, session_id: str) -> dict | None:
    """State derived by the recorder. None when there is no daemon to ask."""
    resp = _request(Path(config_dir), {"op": "state", "session_id": session_id})
    return resp if resp and resp.get("ok") else None


def verify(config_dir: str | os.PathLike) -> dict | None:
    resp = _request(Path(config_dir), {"op": "verify"})
    return resp if resp and resp.get("ok") else None
