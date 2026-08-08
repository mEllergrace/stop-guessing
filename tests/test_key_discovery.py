"""Where an *installed* toolchain looks for its chain key.

Regression for a defect found by installing the toolchain and running it: the
installer generates a mode-600 keyfile at a known path, and nothing ever looked
there. Every command consulted `$STOP_GUESSING_CHAIN_KEY` alone, found nothing,
and refused — `prove` refused, `caiq derive` refused, `attest --self` reported
GOAL NOT MET — with a tier-2 key sitting on disk beside them.

This is the toolchain's own thesis pointed at itself: a primitive can be present
and correct while the installed path never invokes it. `resolve()` had supported
three providers since it was written, and had no callers.
"""

import os

import pytest

from stop_guessing.attest import keys


@pytest.fixture
def no_ambient_key(monkeypatch):
    """The developer's own environment must not decide these outcomes."""
    monkeypatch.delenv(keys.ENV_VAR, raising=False)
    monkeypatch.delenv("CLAUDE_CONFIG_DIR", raising=False)
    # Keychain lookups are a real `security` invocation; keep them out of tests
    # unless a test is specifically about them.
    monkeypatch.setattr(keys, "from_keychain", lambda *a, **k: None)


def write_key(path, material=b"k" * keys.KEY_BYTES):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(material)
    path.chmod(0o600)
    return path


# -- where the installer puts it ----------------------------------------------


def test_installed_keyfile_matches_what_install_sh_writes(no_ambient_key, tmp_path):
    """install.sh writes "$claude_dir/stop-guessing/chain.key"."""
    assert keys.installed_keyfile(tmp_path) == tmp_path / "stop-guessing" / "chain.key"


def test_installed_keyfile_follows_claude_config_dir(no_ambient_key, monkeypatch, tmp_path):
    monkeypatch.setenv("CLAUDE_CONFIG_DIR", str(tmp_path))
    assert keys.installed_keyfile() == tmp_path / "stop-guessing" / "chain.key"


def test_installed_keyfile_defaults_to_the_standard_profile(no_ambient_key):
    assert str(keys.installed_keyfile()).endswith("/.claude/stop-guessing/chain.key")


# -- the defect, as a test ----------------------------------------------------


def test_an_installed_keyfile_is_found_with_no_environment_variable(
    no_ambient_key, monkeypatch, tmp_path
):
    """The whole bug in one assertion."""
    monkeypatch.setenv("CLAUDE_CONFIG_DIR", str(tmp_path))
    write_key(tmp_path / "stop-guessing" / "chain.key")

    got = keys.discover()

    assert got is not None, "the installer's own keyfile must be discoverable"
    key, source = got
    assert source.provider == "keyfile"
    assert source.tier == 2


def test_discovery_returns_none_rather_than_raising_when_there_is_no_key(
    no_ambient_key, monkeypatch, tmp_path
):
    """Callers decide whether to refuse; discovery does not decide for them."""
    monkeypatch.setenv("CLAUDE_CONFIG_DIR", str(tmp_path))
    assert keys.discover() is None


# -- precedence: every existing route still wins where it used to -------------


def test_an_explicit_keyfile_beats_the_installed_one(no_ambient_key, monkeypatch, tmp_path):
    monkeypatch.setenv("CLAUDE_CONFIG_DIR", str(tmp_path))
    write_key(tmp_path / "stop-guessing" / "chain.key", b"i" * keys.KEY_BYTES)
    explicit = write_key(tmp_path / "elsewhere" / "mine.key", b"e" * keys.KEY_BYTES)

    key, source = keys.discover(explicit)

    assert key.material == b"e" * keys.KEY_BYTES


def test_the_environment_still_works_when_nothing_else_is_present(
    no_ambient_key, monkeypatch, tmp_path
):
    """The CI and test route must not be broken by adding discovery."""
    import base64

    monkeypatch.setenv("CLAUDE_CONFIG_DIR", str(tmp_path))
    monkeypatch.setenv(keys.ENV_VAR, base64.b64encode(b"v" * keys.KEY_BYTES).decode())

    got = keys.discover()

    assert got is not None
    assert got[1].provider == "env"
    assert got[1].tier == 1


def test_the_installed_keyfile_beats_the_environment(no_ambient_key, monkeypatch, tmp_path):
    """Tier 2 over tier 1: a key on disk at mode 600 is less readable than one
    in an environment variable every subprocess inherits."""
    import base64

    monkeypatch.setenv("CLAUDE_CONFIG_DIR", str(tmp_path))
    monkeypatch.setenv(keys.ENV_VAR, base64.b64encode(b"v" * keys.KEY_BYTES).decode())
    write_key(tmp_path / "stop-guessing" / "chain.key", b"f" * keys.KEY_BYTES)

    key, source = keys.discover()

    assert source.provider == "keyfile"
    assert key.material == b"f" * keys.KEY_BYTES


def test_the_keychain_beats_everything(monkeypatch, tmp_path):
    """The only provider the recorded agent cannot read stays on top."""
    monkeypatch.setenv("CLAUDE_CONFIG_DIR", str(tmp_path))
    write_key(tmp_path / "stop-guessing" / "chain.key")
    sentinel = (keys.ChainKey("kc-1", b"c" * keys.KEY_BYTES), keys.KeySource("keychain", "kc-1", 3, "login keychain"))
    monkeypatch.setattr(keys, "from_keychain", lambda *a, **k: sentinel)
    monkeypatch.setenv("USER", "somebody")

    assert keys.discover()[1].provider == "keychain"


def test_env_can_be_refused_explicitly(no_ambient_key, monkeypatch, tmp_path):
    """A caller that will not accept a tier-1 key must be able to say so."""
    import base64

    monkeypatch.setenv("CLAUDE_CONFIG_DIR", str(tmp_path))
    monkeypatch.setenv(keys.ENV_VAR, base64.b64encode(b"v" * keys.KEY_BYTES).decode())

    assert keys.discover(allow_env=False) is None


def test_resolve_is_untouched(no_ambient_key, monkeypatch, tmp_path):
    """`discover` is added alongside `resolve`, not in place of it — anything
    already calling resolve() keeps its exact behaviour."""
    keyfile = write_key(tmp_path / "k.key")

    key, source = keys.resolve(keyfile=keyfile)

    assert source.provider == "keyfile"
    with pytest.raises(keys.KeyUnavailable):
        keys.resolve(allow_env=False)


# -- the gate uses it too -----------------------------------------------------


def test_the_hook_gate_finds_an_installed_key(no_ambient_key, monkeypatch, tmp_path):
    """The hook runs inside an installed profile; that is exactly where the
    keyfile lives and exactly where it was not being looked for."""
    monkeypatch.setenv("CLAUDE_CONFIG_DIR", str(tmp_path))
    write_key(tmp_path / "stop-guessing" / "chain.key")

    from stop_guessing.cli import gate

    assert gate.chain_key() is not None
    assert gate._chain_algo() == "hmac-sha256"


def test_the_hook_gate_still_reports_unkeyed_with_no_key(no_ambient_key, monkeypatch, tmp_path):
    monkeypatch.setenv("CLAUDE_CONFIG_DIR", str(tmp_path))

    from stop_guessing.cli import gate

    assert gate.chain_key() is None
    assert gate._chain_algo() == "sha256"


# -- the compat gate's own robustness -----------------------------------------


def test_the_vendored_hook_seeder_ignores_directories(tmp_path):
    """An installed runtime grows __pycache__ inside the vendored hooks. copy2
    on a directory raised IsADirectoryError and took out the entire acceptance
    gate for superseding no-noodles."""
    from stop_guessing.compat import replay

    fake = tmp_path / "vendored"
    (fake / "__pycache__").mkdir(parents=True)
    (fake / "__pycache__" / "x.pyc").write_bytes(b"\x00")
    (fake / "no_noodle.sh").write_text("#!/bin/sh\nexit 0\n")
    (fake / "UPSTREAM_VERSION").write_text("1.2.3\n")

    import stop_guessing.compat.replay as replay_mod

    original = replay_mod.vendored_dir
    replay_mod.vendored_dir = lambda: fake
    try:
        cfg = replay._seed_config_dir(tmp_path / "work")
    finally:
        replay_mod.vendored_dir = original

    names = sorted(p.name for p in (cfg / "hooks").iterdir())
    assert names == ["no_noodle.sh"]
    assert os.access(cfg / "hooks" / "no_noodle.sh", os.X_OK)


# -- an existing ledger's key beats a better one ------------------------------


def test_keyid_of_ledger_reads_the_recorded_keyid(tmp_path):
    import json

    led = tmp_path / "proofs.jsonl"
    led.write_text(json.dumps({"seq": 0, "keyid": "sg-env-abc123", "hash_alg": "hmac-sha256"}) + "\n")

    assert keys.keyid_of_ledger(led) == "sg-env-abc123"


def test_keyid_of_a_missing_or_unreadable_ledger_is_none(tmp_path):
    assert keys.keyid_of_ledger(tmp_path / "nope.jsonl") is None
    bad = tmp_path / "bad.jsonl"
    bad.write_text("{not json\n")
    assert keys.keyid_of_ledger(bad) is None


def test_prefer_keyid_wins_over_the_better_protected_provider(
    no_ambient_key, monkeypatch, tmp_path
):
    """The regression this exists for: promoting a stronger key mid-chain makes
    every prior entry fail verification and get reported as tampering."""
    import base64

    monkeypatch.setenv("CLAUDE_CONFIG_DIR", str(tmp_path))
    monkeypatch.setenv(keys.ENV_VAR, base64.b64encode(b"v" * keys.KEY_BYTES).decode())
    write_key(tmp_path / "stop-guessing" / "chain.key", b"f" * keys.KEY_BYTES)

    env_only = keys.from_env()
    assert env_only is not None
    env_keyid = env_only[0].keyid

    key, source = keys.discover(prefer_keyid=env_keyid)

    assert source.provider == "env", "the ledger's own key must win for an existing chain"
    assert key.keyid == env_keyid


def test_prefer_keyid_falls_back_when_no_provider_has_that_key(
    no_ambient_key, monkeypatch, tmp_path
):
    """An unknown keyid must not mean 'no key at all' — the caller still gets the
    best available one, and the sink reports the mismatch clearly."""
    monkeypatch.setenv("CLAUDE_CONFIG_DIR", str(tmp_path))
    write_key(tmp_path / "stop-guessing" / "chain.key")

    got = keys.discover(prefer_keyid="sg-env-nothinghasthis")

    assert got is not None
    assert got[1].provider == "keyfile"


# -- a wrong key is not tampering ---------------------------------------------


def test_a_wrong_key_is_reported_as_a_mismatch_not_as_tampering(tmp_path):
    from stop_guessing.ledger.chain import ChainKey
    from stop_guessing.ledger.sink import LedgerError, record

    led = tmp_path / "proofs.jsonl"
    original = ChainKey("sg-env-original", b"o" * keys.KEY_BYTES)
    record(led, {"op": "test", "claim": "CLAIM-01"}, original)

    other = ChainKey("sg-kf-different", b"d" * keys.KEY_BYTES)
    with pytest.raises(LedgerError) as excinfo:
        record(led, {"op": "test", "claim": "CLAIM-02"}, other)

    message = str(excinfo.value)
    assert "KEY MISMATCH" in message
    assert "sg-env-original" in message and "sg-kf-different" in message
    assert "edited in place" not in message
    assert "do not" in message and "altered" in message


def test_the_right_key_still_appends_normally(tmp_path):
    from stop_guessing.ledger.chain import ChainKey
    from stop_guessing.ledger.sink import record

    led = tmp_path / "proofs.jsonl"
    key = ChainKey("sg-env-original", b"o" * keys.KEY_BYTES)
    record(led, {"op": "test", "claim": "CLAIM-01"}, key)
    record(led, {"op": "test", "claim": "CLAIM-02"}, key)

    assert sum(1 for line in led.open() if line.strip()) == 2


# ── the provider prefix is not part of the key's identity ────────────────────


def test_the_same_material_read_from_two_providers_is_the_same_key(tmp_path, monkeypatch):
    """`_keyid` is `sg-<provider>-<digest>`, so identity must ignore the provider.

    An operator moving their chain key out of the environment and into a mode-600 keyfile is
    IMPROVING their posture — tier 1 to tier 2. Comparing whole keyids told them the ledger had been
    written under a different key, so every entry was reported as failing its MAC. The MAC is over
    the material and verifies fine; only the comparison was wrong. Same false-tampering family as
    #90, reached from the other direction: there the wrong key was picked, here the right one was
    rejected.
    """
    material = b"m" * keys.KEY_BYTES
    kf = tmp_path / "chain.key"
    kf.write_bytes(material)
    kf.chmod(0o600)
    monkeypatch.setenv(keys.ENV_VAR, material.decode())

    from_file = keys.from_keyfile(kf)[0].keyid
    from_env = keys.from_env()[0].keyid

    assert from_file != from_env, "the provider prefix should still distinguish the SOURCE"
    assert keys.same_key(from_file, from_env), "the same key material read twice is one key"
    assert keys.key_fingerprint(from_file) == keys.key_fingerprint(from_env)


def test_different_material_is_never_the_same_key():
    """The control: stripping the prefix must not make unrelated keys collide."""
    a = keys._keyid(b"a" * keys.KEY_BYTES, "env")
    b = keys._keyid(b"b" * keys.KEY_BYTES, "kf")
    assert not keys.same_key(a, b)


def test_discover_accepts_the_ledgers_key_from_a_different_provider(tmp_path, monkeypatch):
    """The behaviour that matters: `--keyfile` must satisfy a ledger written under `$ENV`."""
    material = b"z" * keys.KEY_BYTES
    kf = tmp_path / "chain.key"
    kf.write_bytes(material)
    kf.chmod(0o600)
    monkeypatch.delenv(keys.ENV_VAR, raising=False)

    wrote_under = keys._keyid(material, "env")          # the ledger says: written from the env
    got = keys.discover(kf, prefer_keyid=wrote_under)   # the operator supplies it as a keyfile
    assert got is not None
    assert keys.same_key(got[0].keyid, wrote_under), (
        "supplying the ledger's own key via --keyfile was rejected as the wrong key")


def test_same_key_is_false_when_either_side_is_missing():
    assert not keys.same_key(None, "sg-env-abc123abc123")
    assert not keys.same_key("sg-env-abc123abc123", None)
