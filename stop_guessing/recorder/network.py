"""Offline by default — asserted by audit, not by policy statement.

The claim is that no runtime path performs an external network call unless anchoring is
explicitly enabled. A claim like that is worth exactly as much as the check behind it, so this
module actually looks: it greps the shipped package for the network APIs that could make a call,
and reports every site with its file and line.

Allowed exceptions are named individually, not by module. "the attest module may use the network"
is how an exception becomes a hole.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

#: Call shapes that reach the network. Deliberately broad — a false positive is a line to read.
NETWORK_PATTERNS = {
    "urllib": r"\burllib\.request\b|\burlopen\b",
    "requests": r"\brequests\.(get|post|put|patch|delete|head|request)\b",
    "httpx": r"\bhttpx\.(get|post|put|Client|AsyncClient)\b",
    "socket": r"\bsocket\.(socket|create_connection)\b",
    "http.client": r"\bhttp\.client\.(HTTPConnection|HTTPSConnection)\b",
    "aiohttp": r"\baiohttp\.",
    "ftplib": r"\bftplib\b",
    "smtplib": r"\bsmtplib\b",
    # Only an INVOCATION counts, not a mention. `if "curl" in text` is not a network call, and
    # a pattern that cannot tell the difference makes the audit cry wolf until nobody reads it.
    "curl-subprocess": r"\[\s*[\"'](?:/usr/bin/)?(?:curl|wget)[\"']|[\"'](?:curl|wget)[\"']\s*,",
}

#: Named, individual exceptions. Each must say why.
ALLOWED = {
    # (relative path, pattern name): reason
    ("attest/tsa.py", "urllib"): "RFC 3161 timestamping — opt-in, off by default, banner on enable",
}

#: Not part of the shipped runtime.
SKIP_DIRS = {"compat/nonoodles", "__pycache__"}


#: A unix domain socket is local IPC and reaches no network. `socket.socket(socket.AF_UNIX, ...)`
#: cannot leave the host — it has no address family that could. The scanner matched the generic
#: `socket.socket(` shape and flagged the recorder's own client and daemon as network call sites,
#: which is a false positive of the worst kind here: it makes the offline claim unprovable by
#: pointing at the one component whose whole design is *not* to use the network.
#:
#: This is recognised by ADDRESS FAMILY on the line, not by an entry in ALLOWED, because a
#: path-based exemption would also excuse a real AF_INET socket appearing in the same file later.
LOCAL_IPC = re.compile(r"\bAF_UNIX\b")


@dataclass(frozen=True)
class Site:
    path: str
    line: int
    pattern: str
    text: str

    @property
    def local_ipc(self) -> bool:
        """A unix-socket call site: local IPC, not egress."""
        return self.pattern == "socket" and bool(LOCAL_IPC.search(self.text))

    @property
    def allowed(self) -> bool:
        return self.local_ipc or (self.path, self.pattern) in ALLOWED

    @property
    def reason(self) -> str:
        if self.local_ipc:
            return "AF_UNIX — local IPC, no network address family"
        return ALLOWED.get((self.path, self.pattern), "")


def audit(package_root: Path) -> dict:
    """Every network call site in the shipped package."""
    sites: list[Site] = []
    scanned = 0
    for py in sorted(package_root.rglob("*.py")):
        rel = str(py.relative_to(package_root))
        if any(skip in rel for skip in SKIP_DIRS):
            continue
        scanned += 1
        for i, line in enumerate(py.read_text(encoding="utf-8").splitlines(), 1):
            stripped = line.strip()
            if stripped.startswith("#") or stripped.startswith('"'):
                continue
            for name, pat in NETWORK_PATTERNS.items():
                if re.search(pat, line):
                    sites.append(Site(rel, i, name, stripped[:100]))
    unexpected = [s for s in sites if not s.allowed]
    return {
        "files_scanned": scanned,
        "sites": [s.__dict__ | {"allowed": s.allowed} for s in sites],
        "unexpected": [s.__dict__ for s in unexpected],
        "offline_by_default": not unexpected,
    }
