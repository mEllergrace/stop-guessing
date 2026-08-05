#!/usr/bin/env python3
# build-ok: searched scripts/ (attest_guard.py guards attestation regressions, hygiene_sweep.py runs
# repo-hygiene's three detectors, stamp_version.py stamps manifests — none reads an audit finding
# list), stop_guessing/prove/ (procedures prove CLAIMS, not audit findings), and
# /Users/isme/Software/repo-hygiene/checks/ (hardcoded-paths, vendored-code, stale-docs only).
# Nothing mechanically re-checks an external audit's findings, which is what "then fix and
# reconfirm all issues" requires: the same check must run before and after the fix.
"""Mechanically re-check the 2026-08-04 hardening audit's findings against the source.

    scripts/audit_verify.py                 # report every finding
    scripts/audit_verify.py --json          # machine-readable
    scripts/audit_verify.py --id SG-HARD-004
    scripts/audit_verify.py --status PRESENT

Each finding gets a predicate over the current tree. Three outcomes, and the third one is the
honest one:

    PRESENT   the defect is still there, with the evidence that shows it
    ABSENT    the predicate no longer holds — the defect appears fixed
    DYNAMIC   not statically decidable; needs a live adversarial test, and saying so is the point

DYNAMIC is not a pass. The audit itself could not execute anything ("Could not resolve host"), so
its dynamic findings are inferences from source. Recording them as DYNAMIC keeps that distinction
instead of laundering an inference into a verified result — which is the exact causation this
project exists to reverse.

A check answers "is the defect still present", never "is the code good". When a fix lands, the
predicate flips to ABSENT and that is the reconfirmation.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent

PRESENT, ABSENT, DYNAMIC = "PRESENT", "ABSENT", "DYNAMIC"


def _read(rel: str) -> str:
    p = REPO / rel
    try:
        return p.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def _has(rel: str, pattern: str) -> bool:
    return re.search(pattern, _read(rel)) is not None


def _count(rel: str, pattern: str) -> int:
    return len(re.findall(pattern, _read(rel), re.M))


def _code(rel: str) -> str:
    """Source with docstrings and comments stripped.

    A predicate that greps raw text finds the word it is looking for in prose. `segments.py` opens
    with \"Seal and archive, rather than rotate and truncate\" — matching `archive` there reported
    SG-HARD-030 as ABSENT while `seal()` performed no archiving at all. A verifier that reads a
    docstring as an implementation is worse than no verifier, so predicates about behaviour run
    against code only.
    """
    src = _read(rel)
    src = re.sub(r'"""(?:.|\n)*?"""', "", src)
    src = re.sub(r"'''(?:.|\n)*?'''", "", src)
    return re.sub(r"(?m)#.*$", "", src)


@dataclass
class Finding:
    id: str
    severity: str
    title: str
    files: list[str]
    check: object = None
    claims: list[str] = field(default_factory=list)

    def run(self) -> tuple[str, str]:
        if self.check is None:
            return DYNAMIC, "no static predicate; requires a live adversarial test"
        try:
            return self.check()
        except Exception as exc:  # noqa: BLE001
            return DYNAMIC, f"predicate could not run: {exc}"


# ── predicates ───────────────────────────────────────────────────────────────


def c_surface_unvalidated():
    src = _code("stop_guessing/prove/runner.py")
    uses = re.search(r"""\bsurface\b""", src.split("def attest_self")[0])
    return (ABSENT, "runner.check() references surface") if uses else (
        PRESENT, "no reference to claims.yaml `surface` anywhere in runner.check()")


def c_missing_procedure_still_proven():
    src = _code("stop_guessing/prove/runner.py")
    lenient = re.search(r"kind_ok\s*=\s*proc is None", src)
    in_proven = re.search(r'"proven":\s*bool\(live\)[^\n]*has_procedure', src)
    if lenient and not in_proven:
        return PRESENT, ("kind_ok = proc is None or ... ; and `proven` omits has_procedure, "
                         "so deleting a procedure leaves the claim proven")
    return ABSENT, "a missing procedure now invalidates the claim"


def c_truncated_ledger_attests():
    src = _code("stop_guessing/prove/runner.py")
    if "truncated" in src:
        return ABSENT, "runner.py now considers loaded.truncated"
    return PRESENT, ("runner.py never references `truncated`; chain_ok = loaded.chain.intact only, "
                     "so a torn tail leaves the intact prefix attesting")


def c_proof_binds_only_procedure_source():
    src = _code("stop_guessing/prove/registry.py") + _code("stop_guessing/prove/runner.py")
    binds_more = re.search(r"policy_digest|tree_digest|build_digest|subject_digest", src)
    return (ABSENT, "a broader evidence subject is bound") if binds_more else (
        PRESENT, "only inspect.getsource() of the decorated function is pinned")


def c_ci_gate_cannot_fail():
    src = _read(".github/workflows/ci.yml")
    if re.search(r"claims check[^\n]*\|\|\s*rc=\$\?", src) and not re.search(
            r"exit\s+\$?\{?rc", src):
        return PRESENT, "claims check exit code is captured then echoed; the step cannot fail"
    return ABSENT, "the claims gate propagates a failing exit code"


def c_isolated_cannot_reach_tier2():
    """Read where the plist is actually WRITTEN, not where the word appears.

    Third false negative of the same family: explaining in an installer message that tier 2 would
    require a LaunchDaemon put the string "LaunchDaemons" in the file, and a substring check read
    that as the daemon being used. Prose about a mechanism is not the mechanism.
    """
    src = _read("install.sh")
    written = re.findall(r'plist=["\']?(\$HOME/Library/LaunchAgents|/Library/LaunchDaemons)', src)
    sets_tier2 = re.search(r"^\s*tier=2\s*$", src, re.M)
    if "/Library/LaunchDaemons" in written:
        return ABSENT, "install.sh writes a plist into /Library/LaunchDaemons"
    if written:
        return PRESENT, (
            f"the plist is written to {written[0]}, which launchd runs as the logged-in user, so "
            f"the recorder shares the agent's uid"
            + ("" if sets_tier2 else "; the installer no longer reports tier 2 for it")
        )
    return DYNAMIC, "could not locate the plist target in install.sh"


def c_same_uid_key_not_isolated():
    """Extract the ACTUAL promotion threshold from strength(), not the words around it.

    Fourth false negative of the same family. Writing "tier 1 is same-uid" in a comment explaining
    the fix made a prose-reading predicate match and report the defect present forever; reading raw
    text also made it match the docstring. Behaviour predicates read code only, and this one
    resolves the named constant rather than pattern-matching the comparison.
    """
    src = _code("stop_guessing/ledger/entry.py")
    m = re.search(r"def strength.*?(?=\n@|\ndef |\nclass )", src, re.S)
    body = m.group(0) if m else ""
    cmp_ = re.search(r"isolation_tier[^\n]*?>=\s*([A-Za-z_0-9]+)", body)
    if not cmp_:
        return DYNAMIC, "could not locate the isolation threshold in strength()"
    token = cmp_.group(1)
    if token.isdigit():
        threshold = int(token)
    else:
        const = re.search(rf"^{re.escape(token)}\s*=\s*(\d+)", src, re.M)
        if not const:
            return DYNAMIC, f"threshold is the symbol {token}, which could not be resolved"
        threshold = int(const.group(1))
    if threshold < 2:
        return PRESENT, (f"strength() promotes to '+isolated' at isolation_tier >= {threshold}; "
                         "tier 1 is a separate process on the SAME uid")
    return ABSENT, (f"'+isolated' requires isolation_tier >= {threshold}, i.e. a different uid; "
                    "same-uid tier 1 now reports plain 'chain-keyed'")


def c_posttooluse_bypasses_daemon():
    src = _code("stop_guessing/cli/hook_post.py")
    direct = "from stop_guessing.ledger.sink import record" in src or re.search(
        r"\brecord\(ledger_path\(\)", src)
    via_client = "recorder.client" in src or "client.append" in src
    if direct and not via_client:
        return PRESENT, "hook_post calls ledger.sink.record() directly, never recorder.client.append()"
    return ABSENT, "PostToolUse routes through the recorder client"


def c_failure_event_unregistered():
    hooks = _read(".claude-plugin/plugins/stop-guessing/hooks/hooks.json")
    if "PostToolUseFailure" in hooks:
        return ABSENT, "PostToolUseFailure is registered"
    return PRESENT, "PostToolUseFailure is a documented event and is not registered"


def c_hook_coverage():
    hooks = _read(".claude-plugin/plugins/stop-guessing/hooks/hooks.json")
    try:
        doc = json.loads(hooks)
    except ValueError:
        return DYNAMIC, "hooks.json is not parseable"
    events = sorted(doc.get("hooks", doc).keys()) if isinstance(doc, dict) else []
    n = len(events)
    if n >= 8:
        return ABSENT, f"{n} events registered: {', '.join(events)}"
    return PRESENT, (f"{n} of 31 documented events registered ({', '.join(events)}); no session "
                     f"boundary, prompt lineage, compaction, batch or reconciliation evidence")


def c_socket_unauthenticated():
    src = _code("stop_guessing/recorder/daemon.py")
    if re.search(r"SO_PEERCRED|LOCAL_PEERCRED|getsockopt.*PEERCRED|peer_cred", src):
        return ABSENT, "the daemon checks peer credentials"
    return PRESENT, "no peer-credential check; any local process may append arbitrary event content"


def c_schema_not_enforced_at_sink():
    sink = _code("stop_guessing/ledger/sink.py")
    daemon = _code("stop_guessing/recorder/daemon.py")
    enforced = "validate_tier_a" in sink or "validate_tier_a" in daemon
    return (ABSENT, "Tier-A validation runs at the sink/daemon boundary") if enforced else (
        PRESENT, "validate_tier_a() is only reachable via CustodyRecord.build(); "
                 "sink.record() and daemon op_append() accept any dict")


def c_doctor_blind():
    """Read the ARGUMENTS to self_check(), not the surrounding function.

    The first version of this predicate searched cmd_doctor's whole body and matched
    `rep.isolation_tier` inside a print() — reporting the defect ABSENT because doctor *displays*
    a tier it was never given the inputs to compute. What doctor passes in is the only thing that
    decides whether it can see the installed architecture.
    """
    src = _code("stop_guessing/cli/cmd_ops.py")
    m = re.search(r"def cmd_doctor.*?(?=\ndef )", src, re.S)
    body = m.group(0) if m else ""
    call = re.search(r"self_check\((.*?)\)", body, re.S)
    args = call.group(1) if call else ""
    if re.search(r"settings|daemon|peer|uid", args, re.I):
        return ABSENT, f"doctor passes installed state into self_check({args.strip()[:80]}…)"
    return PRESENT, ("self_check() receives only "
                     f"{', '.join(a.split('=')[0].strip() for a in args.split(',') if '=' in a)} "
                     "— no settings.json, pinned registration, daemon pid/uid or peer credentials, "
                     "so the reported isolation tier cannot exceed 0")


def c_project_config_can_downgrade():
    src = _code("stop_guessing/cli/hook_gate.py")
    proj_first = re.search(r"cwd\).*\.stop-guessing\.json", src, re.S)
    managed = re.search(r"managed|operator_policy|cannot_weaken", src)
    if proj_first and not managed:
        return PRESENT, ("project .stop-guessing.json precedes profile config and can set "
                         "posture=observe / protect_ledger=false with no managed-policy floor")
    return ABSENT, "a managed policy layer constrains project config"


def c_policy_assets_unanchored():
    src = _code("stop_guessing/cli/gate.py") + _code("stop_guessing/policy/engine.py")
    if re.search(r"expected_policy_digest|verify_policy_digest|pinned_digest", src):
        return ABSENT, "the policy set is checked against a pinned expected digest"
    return PRESENT, "policy_set_digest is recorded but never compared to a trusted expectation"


def c_symlink_classification_bypass():
    src = _code("stop_guessing/cli/gate.py")
    cls = src.find("classify_path(")
    ident = src.find("identify(")
    if cls != -1 and ident != -1 and cls < ident:
        return PRESENT, ("classify_path() runs on the user-supplied spelling at char "
                         f"{cls}; canonicalisation via identify() only at {ident}")
    return ABSENT, "the path is canonicalised before classification"


def c_artifact_id_inode():
    src = _code("stop_guessing/artifacts/identity.py")
    if re.search(r"st_ino|st_dev|inode", src):
        return PRESENT, "artifact_id incorporates dev/inode; atomic replacement mints a new id"
    return ABSENT, "identity no longer depends on inode"


def c_handler_runs_before_policy():
    src = _code("stop_guessing/cli/gate.py")
    sub = src.find("handlers.substitute(")
    ev = src.find(".evaluate(")
    if sub != -1 and ev != -1 and sub < ev:
        return PRESENT, f"handlers.substitute() at char {sub} precedes policy evaluate() at {ev}"
    return ABSENT, "policy authorises before any handler executes"


def c_bar_leaks_handler_output():
    src = _code("stop_guessing/cli/gate.py")
    if "emit_for_model" in src:
        return ABSENT, "the gate routes handler output through emit_for_model()"
    if re.search(r"sub\.output", src):
        return PRESENT, "gate embeds sub.output in the decision reason; emit_for_model() is unused"
    return ABSENT, "handler output is not placed in the decision reason"


def c_no_sandbox():
    src = _code("stop_guessing/delegate.py")
    if re.search(r"sandbox-exec|seatbelt|nsjail|bwrap|unshare|seccomp", src):
        return ABSENT, "an OS sandbox mechanism is invoked"
    return PRESENT, "isolation is an env allowlist plus proxy variables; no OS capability boundary"


def c_cache_fallback_on_integrity_failure():
    src = _code("stop_guessing/cli/gate.py")
    m = re.search(r"def state_for.*?(?=\ndef )", src, re.S)
    body = m.group(0) if m else ""
    broad = re.search(r"except Exception", body)
    distinguishes = re.search(r"unverifiable|integrity_failure", body)
    if broad and not distinguishes:
        return PRESENT, ("state_for() catches Exception broadly, so wrong key / broken chain / "
                         "unreadable ledger all degrade to the agent-writable cache")
    return ABSENT, "absent and unverifiable ledgers are distinguished"


def c_gap_recording_env_only():
    src = _code("stop_guessing/cli/hook_gate.py")
    m = re.search(r"def _record_gap.*?(?=\ndef )", src, re.S)
    body = m.group(0) if m else ""
    if "from_env" in body and "discover" not in body:
        return PRESENT, "_record_gap() uses from_env() only; against an installed keyed ledger it refuses"
    return ABSENT, "_record_gap uses normal key discovery"


def c_seal_does_not_rotate():
    src = _code("stop_guessing/ledger/segments.py")
    if re.search(r"os\.rename\(|os\.replace\(|shutil\.move\(", src):
        return ABSENT, "seal performs a real archive/rollover (rename/replace/move)"
    return PRESENT, ("seal() writes a MAC sidecar only \u2014 no rename/replace/move anywhere in the "
                     "module, so the active ledger stays appendable after sealing")


def c_partial_write():
    src = _code("stop_guessing/ledger/sink.py")
    if re.search(r"while .*written|memoryview|\.write\(.*\)\s*!=\s*len", src):
        return ABSENT, "writes are looped/length-checked"
    if "os.write" in src:
        return PRESENT, "a single os.write() is assumed to write the whole line; no short-write loop"
    return ABSENT, "os.write is not used directly"


def c_full_reverify_per_append():
    src = _code("stop_guessing/ledger/sink.py")
    m = re.search(r"def _record_locked.*?(?=\ndef |\Z)", src, re.S)
    body = m.group(0) if m else ""
    if re.search(r"load\(|verify\(", body):
        return PRESENT, "every append re-reads and re-verifies the whole ledger — O(n^2) lifetime"
    return ABSENT, "append uses a maintained verified head"


def c_cli_ledger_split_brain():
    cli = _code("stop_guessing/cli/cmd_ledger.py")
    gate = _code("stop_guessing/cli/gate.py")
    cli_default = re.search(r"~?/?\.stop-guessing/ledger\.jsonl|\.stop-guessing.*ledger\.jsonl", cli)
    gate_default = "custody.jsonl" in gate
    if cli_default and gate_default:
        return PRESENT, ("cmd_ledger defaults to ~/.stop-guessing/ledger.jsonl while the hook writes "
                         "$CLAUDE_CONFIG_DIR/stop-guessing/ledger/custody.jsonl")
    return ABSENT, "one resolver serves both"


def c_plugin_not_self_contained():
    root = REPO / ".claude-plugin"
    pys = list(root.rglob("*.py")) if root.is_dir() else []
    hooks = _read(".claude-plugin/plugins/stop-guessing/hooks/hooks.json")
    if not pys and "python3 -m stop_guessing" in hooks:
        return PRESENT, ("0 Python files under the plugin subtree; hooks invoke "
                         "`python3 -m stop_guessing...` resolved from ambient PATH/PYTHONPATH")
    return ABSENT, "the plugin bundles its runtime"


def c_wheel_missing_data():
    src = _read("pyproject.toml")
    if re.search(r"package-data|package_data|include-package-data", src) or (REPO / "MANIFEST.in").is_file():
        return ABSENT, "package data is declared"
    return PRESENT, "no package-data and no MANIFEST.in; a wheel omits VERSION, policy/, rules/"


def c_vendored_hook_missing_silently():
    src = _code("stop_guessing/cli/hook_gate.py")
    m = re.search(r"def run_vendored.*?(?=\ndef )", src, re.S)
    body = m.group(0) if m else ""
    if re.search(r"is_file\(\)[^\n]*\n\s*continue|not .*exists\(\)[^\n]*\n\s*continue", body):
        return PRESENT, "a missing vendored hook is skipped with `continue`; the dispatcher gets more permissive"
    return ABSENT, "a missing required rule fails closed"


def c_ci_no_fetch_claim():
    """Measure the ASSERTION, not words near it.

    The finding is that CLAIM-18 asserts "CI performs no fetch", which is false. The first
    predicate searched the procedure for "no fetch"/"no network" and matched the claim's own
    legitimate scope caveat ("not a proof of no network activity"), so it could never clear. What
    settles this is the claim text plus whether the procedure still FAILS on the CI check.
    """
    stmt = ""
    for m in re.finditer(r"^- id: (CLAIM-\d+)\n(.*?)(?=^- id: |\Z)", _read("docs/claims.yaml"),
                         re.S | re.M):
        if m.group(1) == "CLAIM-18":
            stmt = " ".join(m.group(2).split())
    asserts_ci = re.search(r"CI performs no fetch", stmt) and "WITHDRAWN" not in stmt
    src = _code("stop_guessing/prove/procedures.py")
    fails_on_ci = re.search(r'if "curl" in ci or "wget" in ci:\s*\n\s*return r\.fail', src)
    if asserts_ci or fails_on_ci:
        return PRESENT, ("CLAIM-18 still asserts CI performs no fetch"
                         if asserts_ci else
                         "the procedure still fails on literal curl/wget in ci.yml, which equates "
                         "that with 'no fetch'")
    return ABSENT, ("the CI sub-claim is withdrawn in claims.yaml and the procedure now enumerates "
                    "what CI actually fetches instead of denying it")


def c_fill_trusts_editable_yaml():
    src = _code("stop_guessing/cli/cmd_caiq.py")
    m = re.search(r"def cmd_fill.*?(?=\ndef )", src, re.S)
    body = m.group(0) if m else ""
    if "derive(" in body:
        return ABSENT, "cmd_fill re-derives before writing"
    return PRESENT, "cmd_fill reads the editable YAML and writes it without re-deriving from the ledger"


def c_caiq_epoch_circular():
    """Compare the workbook's epoch against APPLICATION claims, not all claims.

    The recursion is cut by excluding the release-attestation claim — the one whose procedure
    writes this document — from both the count it states and the evidence it cites. Its proof
    record does not exist while it is running, so any ref it contributed was stale on arrival.
    Comparing against the all-claims total re-manufactures the very off-by-one that was removed.
    """
    doc = _read("docs/ai-caiq/stop-guessing.yaml")
    m = re.search(r"claims_proven:\s*(\S+)", doc)
    if not m:
        return DYNAMIC, "no claims_proven in the answers file"
    epoch = m.group(1)

    src = _code("stop_guessing/caiq/answers.py")
    declared = re.search(r"RELEASE_ATTESTATION_CLAIMS\s*=\s*frozenset\(\{([^}]*)\}\)", src)
    if not declared:
        return PRESENT, ("no RELEASE_ATTESTATION_CLAIMS: the claim that generates this document is "
                         "still counted inside it, so the artifact and the attestation citing it "
                         "disagree by one, permanently")
    excluded = len(re.findall(r'"CLAIM-\d+"', declared.group(1)))
    n_claims = _count("docs/claims.yaml", r"^\s*-\s*id:\s*CLAIM-\d+")
    app = n_claims - excluded
    if epoch != f"{app}/{app}":
        return PRESENT, (f"the workbook reports {epoch} but there are {app} application claims "
                         f"({n_claims} total minus {excluded} release attestation) — it is stale "
                         "or a claim is unproven")
    if "claims_scope" not in doc:
        return PRESENT, "the epoch does not state its scope, so a reader cannot tell what it counts"
    return ABSENT, (f"the workbook reports {epoch} application claims, states its scope, and "
                    f"excludes the {excluded} release-attestation claim from both the count and "
                    "the evidence — the loop is cut on both halves")


def c_verifier_path_machine_specific():
    src = _code("stop_guessing/caiq/fill.py")
    if re.search(r"/Users/[a-z]+/", src):
        return PRESENT, "fill.py hardcodes an absolute maintainer path to the rich-text verifier"
    return ABSENT, "the verifier is resolved portably"


def c_judge_not_in_verdict():
    src = _code("stop_guessing/prove/runner.py")
    m = re.search(r'result\["goal_met"\]\s*=.*?\n\s*\)', src, re.S)
    body = m.group(0) if m else ""
    if "judge" not in body:
        return PRESENT, "goal_met excludes the judge panel's deferred disapprovals by construction"
    return ABSENT, "the judge participates in the verdict"


def c_claim20_permissive():
    src = _code("stop_guessing/prove/procedures.py")
    m = re.search(r"def prove_every_surface_runs.*?(?=\n@proof|\ndef )", src, re.S)
    body = m.group(0) if m else ""
    if re.search(r"returncode in \(0, 1\)|rc in \(0, 1\)|in \(0, 1\)", body):
        return PRESENT, "CLAIM-20 accepts exit code 1 as a successful surface exercise"
    return ABSENT, "CLAIM-20 requires expected semantics rather than rc in {0,1}"


def c_otel_not_otlp():
    src = _code("stop_guessing/prov/export_otel.py")
    if re.search(r"resourceSpans|scopeSpans", src):
        return ABSENT, "the exporter emits the OTLP resourceSpans/scopeSpans envelope"
    return PRESENT, ("no resourceSpans/scopeSpans envelope; OTLP JSON requires it and encodes enums "
                     "as integers")


def c_export_accepts_truncated():
    src = _code("stop_guessing/cli/cmd_ops.py")
    m = re.search(r"def cmd_export.*?(?=\ndef )", src, re.S)
    body = m.group(0) if m else ""
    if "truncated" in body:
        return ABSENT, "cmd_export checks truncated"
    return PRESENT, "cmd_export checks chain.intact only; a truncated prefix exports as authoritative"


def c_reconcile_unwired():
    """Scan the whole CLI package, not a hardcoded module list.

    The list named four modules, so wiring reconcile() into a NEW hook module would have left this
    reporting the defect present forever. A predicate that only looks where the defect used to live
    cannot observe the fix — the same blindness as matching prose, in a different disguise.
    """
    cli_dir = REPO / "stop_guessing" / "cli"
    files = sorted(p.name for p in cli_dir.glob("*.py")) if cli_dir.is_dir() else []
    hit = [n for n in files
           if re.search(r"from stop_guessing\.ledger\.reconcile import|ledger\.reconcile\.",
                        _code(f"stop_guessing/cli/{n}"))]
    if hit:
        return ABSENT, f"reconcile() is called from a runtime path: {', '.join(hit)}"
    return PRESENT, (f"ledger/reconcile.py is imported by none of the {len(files)} CLI modules, "
                     "so nothing detects a fabricated or replayed execution at runtime")


def c_session_cache_collision():
    src = _code("stop_guessing/taint/persist.py")
    if re.search(r"sha256|blake2|hashlib", src):
        return ABSENT, "the cache filename is a digest of the full session id"
    if re.search(r"\[:120\]|120\]", src):
        return PRESENT, "session id is sanitised and truncated to 120 chars; distinct ids can collide"
    return DYNAMIC, "could not locate the filename derivation"


def c_sufficiency_over_all_records():
    src = _code("stop_guessing/verify/sufficiency.py")
    if re.search(r"event_type|by_type|typed|joined", src):
        return ABSENT, "sufficiency evaluates typed/joined event sets"
    return PRESENT, "sufficiency requires every record to populate every regime; flat events make it permanently incomplete"


def c_page_counts_superseded():
    src = _code("stop_guessing/cli/cmd_page.py")
    if re.search(r'sum\(len\(c\.get\("proofs"\)', src):
        return PRESENT, "the page sums every historical ref rather than current live proofs"
    return ABSENT, "the page renders current live evidence separately from historical runs"


def c_record_id_ambiguous():
    src = _code("stop_guessing/cli/gate.py")
    if re.search(r'f?"sg:\{[^}]*session[^}]*\}:\{[^}]*op', src) or re.search(
            r'sg:\{sid\}:\{op\}', src):
        return PRESENT, "fallback record id is sg:<session>:<op>; repeated ops collide"
    return DYNAMIC, "fallback id shape not located"


def c_disable_switch_silent():
    src = _code("stop_guessing/cli/hook_gate.py")
    if "STOP_GUESSING_DISABLE" in src and not re.search(r"STOP_GUESSING_DISABLE.*\n.*record", src):
        return PRESENT, "STOP_GUESSING_DISABLE bypasses custody with no recorded disabled-mode event"
    return ABSENT, "the disable switch records a transition"


FINDINGS: list[Finding] = [
    Finding("SG-HARD-001", "CRITICAL", "Proof validity ignores the claim's declared surface",
            ["stop_guessing/prove/runner.py", "docs/claims.yaml"], c_surface_unvalidated),
    Finding("SG-HARD-002", "CRITICAL", "A claim stays PROVEN after its procedure is deleted",
            ["stop_guessing/prove/runner.py"], c_missing_procedure_still_proven),
    Finding("SG-HARD-003", "CRITICAL", "Proof staleness binds only the procedure, not the implementation",
            ["stop_guessing/prove/registry.py"], c_proof_binds_only_procedure_source),
    Finding("SG-HARD-004", "CRITICAL", "Truncated proof ledger still yields full attestation",
            ["stop_guessing/prove/runner.py", "stop_guessing/ledger/sink.py"], c_truncated_ledger_attests),
    Finding("SG-HARD-005", "CRITICAL", "CI claims gate accepts every nonzero result",
            [".github/workflows/ci.yml"], c_ci_gate_cannot_fail),
    Finding("SG-HARD-006", "CRITICAL", "--isolated cannot start a separate-UID recorder",
            ["install.sh"], c_isolated_cannot_reach_tier2),
    Finding("SG-HARD-007", "CRITICAL", "Tier 1 and the default keyfile do not separate key from agent",
            ["stop_guessing/ledger/entry.py", "stop_guessing/attest/keys.py"], c_same_uid_key_not_isolated),
    Finding("SG-HARD-008", "CRITICAL", "PostToolUse bypasses cocd and can lose records silently",
            ["stop_guessing/cli/hook_post.py"], c_posttooluse_bypasses_daemon),
    Finding("SG-HARD-009", "CRITICAL", "Failed tool executions are not covered (PostToolUseFailure)",
            [".claude-plugin/plugins/stop-guessing/hooks/hooks.json"], c_failure_event_unregistered),
    Finding("SG-HARD-010", "CRITICAL", "The recorder authenticates ordering, not event truth",
            ["stop_guessing/recorder/daemon.py"], c_socket_unauthenticated),
    Finding("SG-HARD-011", "CRITICAL", "Custody schema is not enforced at the recorder boundary",
            ["stop_guessing/ledger/sink.py", "stop_guessing/recorder/daemon.py"], c_schema_not_enforced_at_sink),
    Finding("SG-HARD-012", "HIGH", "doctor does not inspect the installed architecture",
            ["stop_guessing/cli/cmd_ops.py"], c_doctor_blind),
    Finding("SG-HARD-013", "CRITICAL", "Project-writable config can downgrade enforcement",
            ["stop_guessing/cli/hook_gate.py"], c_project_config_can_downgrade),
    Finding("SG-HARD-014", "CRITICAL", "Rules/policies/handlers are untrusted mutable inputs",
            ["stop_guessing/policy/engine.py", "stop_guessing/cli/gate.py"], c_policy_assets_unanchored),
    Finding("SG-HARD-015", "CRITICAL", "Symlink aliasing bypasses PreToolUse classification",
            ["stop_guessing/cli/gate.py"], c_symlink_classification_bypass),
    Finding("SG-HARD-016", "HIGH", "Artifact identity changes on atomic replacement",
            ["stop_guessing/artifacts/identity.py"], c_artifact_id_inode),
    Finding("SG-HARD-017", "CRITICAL", "Project handler executes on classified data before policy",
            ["stop_guessing/cli/gate.py", "stop_guessing/handlers.py"], c_handler_runs_before_policy),
    Finding("SG-HARD-018", "CRITICAL", "Signed-script execution bypassable by its paired test",
            ["stop_guessing/delegate.py", "stop_guessing/cli/cmd_ops.py"]),
    Finding("SG-HARD-019", "CRITICAL", "Delegation has test/hash/execute TOCTOU races",
            ["stop_guessing/delegate.py"]),
    Finding("SG-HARD-020", "CRITICAL", "bar sends full handler output to model-visible context",
            ["stop_guessing/cli/gate.py"], c_bar_leaks_handler_output),
    Finding("SG-HARD-021", "CRITICAL", "Delegated execution is not sandboxed",
            ["stop_guessing/delegate.py"], c_no_sandbox),
    Finding("SG-HARD-022", "CRITICAL", "State read, decision and append are not atomic",
            ["stop_guessing/cli/gate.py"]),
    Finding("SG-HARD-023", "CRITICAL", "Ledger integrity failure falls back to mutable cache",
            ["stop_guessing/cli/gate.py"], c_cache_fallback_on_integrity_failure),
    Finding("SG-HARD-024", "HIGH", "Gap-recording and decision-recording failures can be silent",
            ["stop_guessing/cli/hook_gate.py"], c_gap_recording_env_only),
    Finding("SG-HARD-025", "CRITICAL", "Ledger replay is not equivalent to live custody state",
            ["stop_guessing/taint/state.py"]),
    Finding("SG-HARD-026", "CRITICAL", "The bytes read into model context are not bound",
            ["stop_guessing/cli/gate.py", "stop_guessing/cli/hook_post.py"]),
    Finding("SG-HARD-027", "HIGH", "Only one 'worst' candidate is evaluated per call",
            ["stop_guessing/cli/gate.py"]),
    Finding("SG-HARD-028", "HIGH", "Shell path and egress heuristics are bypassable",
            ["stop_guessing/artifacts/classify.py"]),
    Finding("SG-HARD-029", "HIGH", "Session-state cache filenames can collide",
            ["stop_guessing/taint/persist.py"], c_session_cache_collision),
    Finding("SG-HARD-030", "HIGH", "Sealing does not archive, rotate or freeze a segment",
            ["stop_guessing/ledger/segments.py"], c_seal_does_not_rotate),
    Finding("SG-HARD-031", "HIGH", "Ledger IO mishandles partial writes and malformed middles",
            ["stop_guessing/ledger/sink.py"], c_partial_write),
    Finding("SG-HARD-032", "HIGH", "Append and daemon design allow exhaustion and downgrade",
            ["stop_guessing/ledger/sink.py", "stop_guessing/recorder/daemon.py"], c_full_reverify_per_append),
    Finding("SG-HARD-033", "HIGH", "CLI and hook use different default ledgers and key discovery",
            ["stop_guessing/cli/cmd_ledger.py", "stop_guessing/cli/gate.py"], c_cli_ledger_split_brain),
    Finding("SG-HARD-034", "CRITICAL", "The plugin package is not self-contained",
            [".claude-plugin/plugins/stop-guessing/hooks/hooks.json"], c_plugin_not_self_contained),
    Finding("SG-HARD-035", "HIGH", "Wheel/sdist packaging omits required runtime assets",
            ["pyproject.toml"], c_wheel_missing_data),
    Finding("SG-HARD-036", "HIGH", "Installer upgrades can leave stale mixed-version code",
            ["install.sh"]),
    Finding("SG-HARD-037", "HIGH", "Installer settings/service changes are non-atomic",
            ["install.sh"]),
    Finding("SG-HARD-038", "HIGH", "Missing vendored hook is silently skipped",
            ["stop_guessing/cli/hook_gate.py"], c_vendored_hook_missing_silently),
    Finding("SG-HARD-039", "HIGH", "CLAIM-18's 'CI performs no fetch' assertion is false",
            ["stop_guessing/prove/procedures.py"], c_ci_no_fetch_claim),
    Finding("SG-HARD-040", "CRITICAL", "CAIQ fill trusts editable YAML without re-deriving",
            ["stop_guessing/cli/cmd_caiq.py"], c_fill_trusts_editable_yaml),
    Finding("SG-HARD-041", "CRITICAL", "CLAIM-21 is circular and spans two evidence epochs",
            ["stop_guessing/prove/procedures.py", "docs/ai-caiq/stop-guessing.yaml"], c_caiq_epoch_circular),
    Finding("SG-HARD-042", "HIGH", "Attestation does not validate CAIQ metadata/mapping",
            ["stop_guessing/prove/runner.py"]),
    Finding("SG-HARD-043", "HIGH", "External CAIQ verification path is machine-specific",
            ["stop_guessing/caiq/fill.py"], c_verifier_path_machine_specific),
    Finding("SG-HARD-044", "HIGH", "Known adequacy objections do not affect the verdict",
            ["stop_guessing/prove/judge.py", "stop_guessing/prove/runner.py"], c_judge_not_in_verdict),
    Finding("SG-HARD-045", "HIGH", "CLAIM-20 checks presence and permissive exit codes",
            ["stop_guessing/prove/procedures.py"], c_claim20_permissive),
    Finding("SG-HARD-046", "HIGH", "OpenTelemetry export is not valid OTLP JSON",
            ["stop_guessing/prov/export_otel.py"], c_otel_not_otlp),
    Finding("SG-HARD-047", "HIGH", "Exports accept a truncated ledger prefix",
            ["stop_guessing/cli/cmd_ops.py"], c_export_accepts_truncated),
    Finding("SG-HARD-048", "HIGH", "Lifecycle and batch events are not registered",
            [".claude-plugin/plugins/stop-guessing/hooks/hooks.json"], c_hook_coverage),
    Finding("SG-HARD-049", "HIGH", "Request/result reconciliation is absent at runtime",
            ["stop_guessing/ledger/reconcile.py"], c_reconcile_unwired),
    Finding("SG-HARD-050", "MEDIUM", "Record ids can collide; disable mode is unaudited",
            ["stop_guessing/cli/gate.py", "stop_guessing/cli/hook_gate.py"], c_disable_switch_silent),
    Finding("SG-HARD-051", "HIGH", "Mixed full/flat records make sufficiency unattainable",
            ["stop_guessing/verify/sufficiency.py"], c_sufficiency_over_all_records),
    Finding("SG-HARD-052", "HIGH", "Strength labels overstate isolation",
            ["stop_guessing/ledger/entry.py"], c_same_uid_key_not_isolated),
    Finding("SG-HARD-053", "HIGH", "Public proof counts include superseded historical refs",
            ["stop_guessing/cli/cmd_page.py"], c_page_counts_superseded),
    Finding("SG-HARD-054", "HIGH", "Generated artifacts disagree and contain stale statements",
            ["docs/ai-caiq/stop-guessing.yaml", "docs/index.html"], c_caiq_epoch_circular),
]


def run_all(ids: list[str] | None = None) -> list[dict]:
    out = []
    for f in FINDINGS:
        if ids and f.id not in ids:
            continue
        status, evidence = f.run()
        out.append({"id": f.id, "severity": f.severity, "title": f.title,
                    "files": f.files, "status": status, "evidence": evidence})
    return out


def head_commit() -> str:
    try:
        return subprocess.run(["git", "rev-parse", "--short", "HEAD"], cwd=str(REPO),
                              capture_output=True, text=True, timeout=30).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return "unknown"


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--id", action="append", help="only these finding ids")
    ap.add_argument("--status", help="only rows with this status")
    args = ap.parse_args(argv)

    rows = run_all(args.id)
    if args.status:
        rows = [r for r in rows if r["status"] == args.status.upper()]

    if args.json:
        print(json.dumps({"commit": head_commit(), "findings": rows}, indent=2))
        return 0

    counts = {PRESENT: 0, ABSENT: 0, DYNAMIC: 0}
    print(f"audit re-verification at {head_commit()} — {len(rows)} finding(s)\n")
    for r in rows:
        counts[r["status"]] = counts.get(r["status"], 0) + 1
        print(f"[{r['status']:<7}] {r['id']} {r['severity']:<8} {r['title']}")
        print(f"           {r['evidence']}")
    print(f"\nPRESENT {counts[PRESENT]}   ABSENT {counts[ABSENT]}   DYNAMIC {counts[DYNAMIC]}")
    print("\nDYNAMIC is not a pass — it means no static predicate can settle it and a live "
          "adversarial test is required.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
