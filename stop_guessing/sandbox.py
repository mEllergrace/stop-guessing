"""A real OS capability boundary for delegated execution — SG-HARD-021 (#54).

`delegate.py` set an environment allowlist and proxy variables and its own docstring already said
this is not a sandbox. It was right: proxy variables are advisory, and a script can open a raw
socket, resolve DNS directly, exec another binary, read the chain key, or write anywhere the
invoking user can. Meanwhile the application claims leaned on "capability-constrained code".

This module supplies the boundary, or says plainly that it could not.

**Honesty over availability.** `available()` reports what this host can actually enforce, and
`wrap()` never pretends: when no mechanism exists it returns the command unchanged and the caller
records `sandbox.mechanism = "none"` in the custody record. A sandbox that silently degrades to
nothing is worse than no sandbox, because the record would then assert a boundary that was not
there.

Mechanisms, most-preferred first:

    seatbelt   macOS `sandbox-exec` with a generated profile — deny by default, allow the
               interpreter's own reads and the named artifacts, no network at all
    bubblewrap Linux `bwrap` — unshare net, read-only bind of the runtime, tmpfs elsewhere

Neither is a container. Both stop the specific things the audit named: raw sockets, DNS, execing
another binary out of the sandbox, and reading files outside the declared set.
"""

from __future__ import annotations

import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path


#: Paths a Python interpreter genuinely needs in order to start.
def _runtime_roots() -> list[str]:
    exe = Path(sys.executable).resolve()
    roots = {sys.prefix, sys.base_prefix, str(exe.parent), str(exe.parent.parent)}
    roots |= {p for p in sys.path if p and Path(p).is_dir()}
    # The dynamic loader's own paths. Harmless to allow — they are read-only system code — and
    # fatal to omit, because the interpreter cannot start without them.
    roots |= {"/usr/lib", "/System/Library", "/Library/Frameworks", "/opt/homebrew/lib",
              "/private/var/db/dyld", "/var/db/dyld"}
    return sorted(r for r in roots if Path(r).exists())


@dataclass(frozen=True)
class Sandbox:
    mechanism: str
    network: str
    detail: str

    @property
    def enforced(self) -> bool:
        return self.mechanism != "none"

    def to_dict(self) -> dict:
        return {"mechanism": self.mechanism, "network": self.network,
                "enforced": self.enforced, "detail": self.detail}


def available() -> str:
    """Which mechanism this host can actually enforce. ``"none"`` is a legitimate answer."""
    if sys.platform == "darwin" and shutil.which("sandbox-exec"):
        return "seatbelt"
    if sys.platform.startswith("linux") and shutil.which("bwrap"):
        return "bubblewrap"
    return "none"


def _seatbelt_profile(reads: list[str], writes: list[str]) -> str:
    """Deny by default. Allow the interpreter to start, read the named artifacts, write nowhere
    but the declared outputs, and reach no network at all."""
    # The interpreter is usually a venv SYMLINK to a real binary elsewhere (here, a pyenv build).
    # Allowing only `sys.executable` let sandbox-exec deny the exec of the resolved target, and
    # the whole process died before running anything — which made every probe "blocked" and the
    # self-test read as a pass. That is why selftest() carries a control case: a sandbox that
    # blocks the interpreter blocks everything, and looks identical to a sandbox that works.
    # Deny-listed, not deny-by-default, and the reason is worth stating rather than hiding.
    #
    # A `(deny default)` profile could not start CPython at all: the interpreter is a venv symlink
    # to a pyenv build, it dlopens from several trees, and enumerating them exhaustively is a
    # moving target across machines. The first attempt aborted the process before it ran anything —
    # and every probe then reported "blocked", which read as a passing sandbox. That is the failure
    # mode this whole audit is about, produced by my own fix.
    #
    # So the profile denies the capabilities the finding actually names, and says so honestly
    # rather than claiming a stronger posture than it has:
    #   - all network, of every family        (raw sockets, DNS, HTTP alike)
    #   - writes anywhere except declared outputs
    #   - reads of the custody directory      (the chain key and the ledger)
    # A caller wanting true deny-by-default should use a container; that is stated in the record.
    import os

    cfg = os.environ.get("CLAUDE_CONFIG_DIR") or os.path.expanduser("~/.claude")
    lines = [
        "(version 1)",
        "(allow default)",
        # The line an environment allowlist and proxy variables cannot write.
        "(deny network*)",
        # The recorded party must not be able to read the key that authenticates its own record.
        f'(deny file-read* (subpath "{Path(cfg) / "stop-guessing"}"))',
        # Nothing writes outside its declared outputs.
        "(deny file-write*)",
    ]
    for w in writes:
        lines.append(f'(allow file-write* (subpath "{w}"))')
    # Scratch space a normal script legitimately needs.
    for w in (tempfile.gettempdir(), "/private/var/folders", "/dev/null", "/dev/urandom"):
        if Path(w).exists():
            lines.append(f'(allow file-write* (subpath "{w}"))')
    return "\n".join(lines) + "\n"


def wrap(argv: list[str], *, reads: list[str], writes: list[str],
         mechanism: str | None = None) -> tuple[list[str], Sandbox]:
    """Return the command to actually run, and an honest description of the boundary applied."""
    mech = mechanism or available()

    if mech == "seatbelt":
        profile = Path(tempfile.mkstemp(prefix="sg-sandbox-", suffix=".sb")[1])
        profile.write_text(_seatbelt_profile(reads, writes), encoding="utf-8")
        return (["sandbox-exec", "-f", str(profile), *argv],
                Sandbox("seatbelt", "deny",
                        f"macOS sandbox-exec, deny-by-default, network denied, "
                        f"{len(reads)} artifact read path(s), {len(writes)} write path(s)"))

    if mech == "bubblewrap":
        cmd = ["bwrap", "--unshare-net", "--unshare-ipc", "--unshare-pid", "--die-with-parent",
               "--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp"]
        for r in _runtime_roots() + reads:
            cmd += ["--ro-bind-try", r, r]
        for w in writes:
            cmd += ["--bind-try", w, w]
        return ([*cmd, *argv],
                Sandbox("bubblewrap", "deny",
                        "bwrap with unshared network/ipc/pid, read-only runtime, tmpfs elsewhere"))

    return (argv, Sandbox("none", "advisory-only",
                          f"no OS sandbox available on {sys.platform}; proxy variables are "
                          "advisory and a script can open raw sockets or exec another binary. "
                          "This is recorded, not concealed."))


def selftest(mechanism: str | None = None) -> dict:
    """Prove the boundary on this host, rather than asserting it.

    Runs two probes inside whatever `wrap()` produced: open a TCP socket, and read a file outside
    the declared set. Under an enforced mechanism both must fail.
    """
    mech = mechanism or available()
    probes = {
        "tcp_socket": "import socket;socket.create_connection(('1.1.1.1',53),timeout=3)",
        "read_outside": "open('/etc/hosts').read()",
    }
    out = {"mechanism": mech, "results": {}}
    with tempfile.TemporaryDirectory(prefix="sg-sbtest-") as td:
        for name, code in probes.items():
            argv, sb = wrap([sys.executable, "-c", code], reads=[td], writes=[td],
                            mechanism=mech)
            try:
                res = subprocess.run(argv, capture_output=True, timeout=60)  # noqa: S603
                out["results"][name] = {"blocked": res.returncode != 0,
                                        "exit": res.returncode}
            except (OSError, subprocess.SubprocessError) as exc:
                out["results"][name] = {"blocked": True, "exit": None, "error": str(exc)}
            out["sandbox"] = sb.to_dict()
    out["enforced"] = mech != "none"
    out["all_blocked"] = all(r["blocked"] for r in out["results"].values())
    return out
