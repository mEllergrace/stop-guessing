"""Where the chain key lives.

A provider chain, ordered most-protected first, modelled on secretarius'
`vault/keyproviders.py`. The property that matters: **the key must be somewhere the recorded
agent cannot read.** On macOS the login keychain qualifies, because reading it requires a
`security` invocation that the gate denies under every posture — including `observe`, where
nothing else is denied.

The environment provider exists for CI and tests and is deliberately reported as the weakest
tier. A key in an environment variable is readable by anything the agent can run, so a ledger
keyed that way is honest about being `chain-keyed` in form only.
"""

from __future__ import annotations

import os
import secrets
import subprocess
from dataclasses import dataclass
from pathlib import Path

from stop_guessing.ledger.chain import ChainKey

ENV_VAR = "STOP_GUESSING_CHAIN_KEY"
KEYCHAIN_SERVICE = "stop-guessing-chain-key"
KEY_BYTES = 32


@dataclass(frozen=True)
class KeySource:
    """Where a key came from, and how much that is worth."""

    provider: str
    keyid: str
    #: 3 keychain, 2 keyfile with restrictive mode, 1 environment, 0 none
    tier: int
    note: str


class KeyUnavailable(Exception):
    """No provider yielded a key. The caller decides whether to proceed unkeyed and say so."""


def _keyid(material: bytes, provider: str) -> str:
    import hashlib

    return f"sg-{provider}-{hashlib.sha256(material).hexdigest()[:12]}"


# ── providers ────────────────────────────────────────────────────────────────


def from_keychain(account: str, *, service: str = KEYCHAIN_SERVICE) -> tuple[ChainKey, KeySource] | None:
    """macOS login keychain. The only provider the recorded agent cannot trivially read."""
    try:
        res = subprocess.run(  # noqa: S603
            ["security", "find-generic-password", "-s", service, "-a", account, "-w"],
            capture_output=True,
            timeout=10,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if res.returncode != 0:
        return None
    raw = res.stdout.decode().strip()
    if not raw:
        return None
    material = bytes.fromhex(raw) if len(raw) == KEY_BYTES * 2 else raw.encode()
    kid = _keyid(material, "kc")
    return ChainKey(kid, material), KeySource(
        "keychain", kid, 3, f"macOS keychain service={service} account={account}"
    )


def from_keyfile(path: str | Path) -> tuple[ChainKey, KeySource] | None:
    """A file on disk. Refuses a group- or world-readable key rather than pretending."""
    p = Path(path)
    if not p.is_file():
        return None
    mode = p.stat().st_mode & 0o777
    if mode & 0o077:
        raise KeyUnavailable(
            f"keyfile {p} has mode {mode:o}; a chain key readable beyond its owner is not a key. "
            f"chmod 600 {p}"
        )
    material = p.read_bytes().strip()
    if not material:
        return None
    kid = _keyid(material, "kf")
    return ChainKey(kid, material), KeySource("keyfile", kid, 2, f"keyfile {p} mode {mode:o}")


def from_env(var: str = ENV_VAR) -> tuple[ChainKey, KeySource] | None:
    """Environment. Weakest tier by construction — anything the agent runs can read it."""
    raw = os.environ.get(var)
    if not raw:
        return None
    material = raw.encode()
    kid = _keyid(material, "env")
    return ChainKey(kid, material), KeySource(
        "env", kid, 1, f"${var} — readable by anything the agent can run"
    )


def resolve(
    *,
    account: str | None = None,
    keyfile: str | Path | None = None,
    allow_env: bool = True,
) -> tuple[ChainKey, KeySource]:
    """First provider that yields a key wins, most-protected first."""
    if account:
        got = from_keychain(account)
        if got:
            return got
    if keyfile:
        got = from_keyfile(keyfile)
        if got:
            return got
    if allow_env:
        got = from_env()
        if got:
            return got
    raise KeyUnavailable(
        "no chain key available. The ledger can still be written unkeyed, but it will be "
        "reported as 'chain-only' strength and a rewrite would not be detectable."
    )


def generate() -> bytes:
    """Fresh key material. `secrets`, never `random`."""
    return secrets.token_bytes(KEY_BYTES)
