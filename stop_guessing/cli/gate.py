"""Turn a hook payload into a custody decision.

Kept small and pure-ish on purpose: `hook_gate` owns the protocol, this owns the judgement, and
the judgement is the part that must be testable without spawning a session.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

from stop_guessing.artifacts.classify import classify_egress, classify_path, paths_in
from stop_guessing.artifacts.identity import identify
from stop_guessing.policy.engine import load
from stop_guessing.taint.state import ArtifactRef, SessionCustodyState
from stop_guessing.version import policy_dir

_POLICIES = None


def ledger_path() -> Path:
    cfg = os.environ.get("CLAUDE_CONFIG_DIR") or os.path.expanduser("~/.claude")
    return Path(cfg) / "stop-guessing" / "ledger" / "custody.jsonl"


def chain_key():
    # The hook runs inside an installed profile, where the key is a mode-600
    # keyfile written by install.sh — not an environment variable. Consulting
    # only the environment meant every hook-written record was unkeyed while a
    # tier-2 key sat at a known path beside it, and `attest --self` reported
    # GOAL NOT MET for want of looking.
    from stop_guessing.attest.keys import discover
    got = discover()
    return got[0] if got else None


def _now() -> str:
    from datetime import UTC, datetime
    return datetime.now(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def policies():
    """Load the policy set, and check it against a pinned expectation when one exists.

    #47/#55 (SG-HARD-014). The gate loads policy and classification rules from a user-writable
    tree, recorded a policy_set_digest, and had nothing to compare that digest AGAINST. An attacker
    who can edit a rule can therefore reclassify a credential as public, and the ledger will
    faithfully record the attacker's policy as if it were the authority — a perfect record of the
    wrong thing.

    `expected_policy_digest` in `managed.json` (outside project write authority) pins it. When it
    is absent, behaviour is exactly as before: nothing is enforced, because inventing an
    expectation nobody set would break every existing install. When it is present and disagrees,
    the mismatch is a critical recorded finding — the gate still runs, because a policy mismatch
    must not become a denial of service against the whole session.
    """
    global _POLICIES
    if _POLICIES is None:
        _POLICIES = load(policy_dir())
        _check_policy_pin(_POLICIES)
    return _POLICIES


def _check_policy_pin(ps) -> None:
    import json as _json

    cfg = Path(os.environ.get("CLAUDE_CONFIG_DIR") or os.path.expanduser("~/.claude"))
    try:
        expected = _json.loads((cfg / "managed.json").read_text(encoding="utf-8")).get(
            "expected_policy_digest")
    except (OSError, ValueError):
        return
    if not expected or expected == ps.digest:
        return
    detail = (f"POLICY SET MISMATCH: loaded {ps.digest[:16]}, managed.json pins "
              f"{str(expected)[:16]}. Decisions from here are being made under a policy the "
              f"operator did not sanction.")
    try:
        from stop_guessing.attest.keys import discover
        from stop_guessing.ledger.sink import record as _record

        got = discover(config_dir=cfg)
        _record(ledger_path(), {
            "op": "policy.load", "actor": "stop-guessing/gate", "severity": "critical",
            "at": _now(), "detail": detail, "known_gaps": [detail], "alterations": [],
        }, got[0] if got else None)
    except Exception:  # noqa: BLE001
        import sys

        print(f"STOP-GUESSING: {detail}", file=sys.stderr)


def _unsafe_state(session_id: str, why: str) -> tuple[SessionCustodyState, bool]:
    """The state to use when the authoritative record cannot be verified.

    NOT the cache. The cache is writable by the recorded party, so trusting it after an integrity
    failure hands the agent exactly the capability the ledger exists to deny it: delete or corrupt
    the ledger, and enforcement resets to untainted.

    A maximally-tainted state is returned instead, so an unverifiable ledger fails toward denying
    egress rather than permitting it, and the reason travels with it as a disagreement the caller
    records.
    """
    st = SessionCustodyState(session_id, labels=frozenset({"restricted"}))
    st.unverifiable_reason = why  # type: ignore[attr-defined]
    return st, False


def state_for(session_id: str) -> tuple[SessionCustodyState, bool]:
    """Ledger-authoritative state, with the JSON file as a cache only.

    Fixes #14. This used to call `persist.load()` directly, so deleting the state file reset
    enforcement to untainted — the recorded party could clear its own taint with `rm`. The
    "ledger is authoritative" comment described a function (`reconcile_with_ledger`) that the
    deployed path never called.

    Now the ledger is replayed and wins on disagreement, and the disagreement itself is a finding
    the caller records rather than swallowing.
    """
    from stop_guessing.ledger.sink import load as load_ledger
    from stop_guessing.recorder import client
    from stop_guessing.taint import persist

    cfg = Path(os.environ.get("CLAUDE_CONFIG_DIR") or os.path.expanduser("~/.claude"))
    # Prefer the recorder's own derivation: the party that owns the history derives the state.
    remote = client.custody_state(cfg, session_id)
    if remote is not None:
        cached = persist.load(session_id)
        return _state_from(remote, session_id), cached.digest == remote["digest"]

    # #59 (SG-HARD-023). This caught Exception broadly and fell through to `records = []`, so a
    # wrong key, an unreadable file, a broken chain and a truncated ledger all became "no records"
    # — indistinguishable from a first run — and the agent-WRITABLE cache was then restored as
    # authority. An integrity failure must never be read as an empty history.
    #
    # ABSENT and UNVERIFIABLE are different states. Absent is normal. Unverifiable is unsafe.
    led = ledger_path()
    if not led.exists():
        return persist.load(session_id), True
    try:
        loaded = load_ledger(led, chain_key())
    except Exception as exc:  # noqa: BLE001
        return _unsafe_state(session_id, f"the ledger could not be read: {exc}")
    if not loaded.usable:
        return _unsafe_state(session_id, loaded.chain.reason or "the ledger does not verify")
    if not loaded.entries:
        return persist.load(session_id), True
    return persist.reconcile_with_ledger(session_id, loaded.entries)


def _state_from(remote: dict, session_id: str) -> SessionCustodyState:
    st = SessionCustodyState(session_id, labels=frozenset(remote["labels"]),
                             touched=remote.get("touched", 0),
                             since_last_egress=remote.get("since_last_egress", 0))
    for aid, d in (remote.get("sources") or {}).items():
        st.sources[aid] = ArtifactRef(aid, d.get("path", ""), d.get("digest"),
                                      frozenset(d.get("labels") or {"public"}))
    return st


def _canonical(path: str) -> str:
    """Resolve symlinks and `..` without touching the file. Never raises."""
    from stop_guessing.artifacts.identity import canonical_path

    try:
        return canonical_path(path)
    except Exception:  # noqa: BLE001 - an unresolvable path must not take the call down
        return path


def _join_classification(a, b):
    """Union two classifications of the same artifact. Labels only ever accumulate.

    #56: an alias must never be able to REMOVE a label — that is the whole bypass. Joining is
    monotone, so whichever spelling carries the classification, the call is classified.
    """
    from stop_guessing.artifacts.classify import Classification

    return Classification(
        labels=frozenset(a.labels) | frozenset(b.labels),
        matched=tuple(dict.fromkeys((*a.matched, *b.matched))),
        sources=tuple(dict.fromkeys((*a.sources, *b.sources))),
    )


def decide(payload: dict, posture: str = "observe") -> dict | None:
    """Returns a decision dict, or None when nothing custody-relevant is happening.

    Every decision is appended to the keyed ledger before it is returned (#13). Previously the
    gate emitted a decision and wrote nothing durable, so the installed plugin produced no custody
    record at all.
    """
    tool = payload.get("tool_name", "")
    tool_input = payload.get("tool_input", {}) or {}
    session_id = payload.get("session_id", "unknown")
    state, cache_agreed = state_for(session_id)
    ps = policies()

    command = tool_input.get("command", "") if tool == "Bash" else ""
    egress = classify_egress(command) if command else None
    is_write = tool in ("Write", "Edit", "NotebookEdit")

    # #56 (SG-HARD-015). Classification ran on the SPELLING the caller supplied and only
    # canonicalised afterwards for identity, so a benignly named symlink — /tmp/public.txt
    # pointing at ~/.ssh/id_rsa — classified as public and its contents entered model context.
    # PostToolUse canonicalises, which is after the bytes have already been read.
    #
    # Both forms are classified now and the labels are joined, so an alias can only ever ADD
    # labels. Neither spelling can be used to shed the other's classification, and the aliasing
    # itself is recorded rather than resolved away silently.
    candidates = paths_in(tool, tool_input)
    worst = None
    aliases: list[dict] = []
    for p in candidates:
        c = classify_path(p)
        canon = _canonical(p)
        if canon != p:
            c_canon = classify_path(canon)
            if c_canon.classified and not c.classified:
                aliases.append({"given": p, "resolves_to": canon,
                                "labels_gained": sorted(c_canon.labels)})
            c = _join_classification(c, c_canon)
        if c.classified and (worst is None or len(c.labels) > len(worst[1].labels)):
            worst = (p, c)

    if worst is None and not (egress and egress.is_egress):
        return None

    if worst is not None:
        path, c = worst
        # Stable identity (#15). `hash()` is salted per interpreter and every hook invocation is a
        # fresh interpreter, so the previous id changed on every call.
        ident = identify(path, digest_content=False)
        art_id = ident.artifact_id
        first_touch = art_id not in state.sources
        artifact = {"id": art_id, "labels": sorted(c.labels), "classified": True,
                    "has_handler": False,
                    "first_touch": first_touch,
                    "canonical_path": ident.canonical_path,
                    # #56: an alias that only became classified once resolved is itself the
                    # finding. Recording it means an auditor sees the attempt, not just the
                    # eventual correct label.
                    "aliases": aliases,
                    "requested_path": path,
                    "is_ledger": "stop-guessing" in ident.canonical_path
                    and "ledger" in ident.canonical_path}
    else:
        path, c, art_id, first_touch = "", None, "", False
        ident = None
        artifact = {"classified": False, "first_touch": False, "is_ledger": False}

    call = {
        "is_egress": bool(egress and egress.is_egress),
        "is_write": is_write,
        "is_own_binary": "stop-guessing" in command and "ledger" not in command,
        "markers": [m for m in ("# noodle-ok", "# risk-ok", "# custody-ok") if m in command],
        # Configurable, defaulting to on. Protecting the ledger is the one refusal that outlives
        # `observe`, so it gets an explicit switch rather than being unconditional.
        "protect_ledger": _protect_ledger(),
    }
    # A classified read with a registered handler is SATISFIED, not blocked and not waved
    # through: the handler runs, the model receives its output, and the file's contents never
    # enter context. No handler means no substitution and the call proceeds as it would have —
    # a missing handler must never become a refusal.
    #
    # #50 (SG-HARD-017). This used to RUN the handler — and its unsigned paired pytest — against
    # the classified artifact BEFORE policy was evaluated. A project-controlled handlers/index.yaml
    # could therefore execute project code on the file under `bar`, read it and write it anywhere,
    # and only then would the policy decision deny the original read. The denial arrived after the
    # data had already been handled.
    #
    # Discovery and execution are now separated. `find()` only reads the index, which is enough to
    # tell the policy that a handler EXISTS; nothing runs until the policy has authorised it.
    handler = None
    substitution = None
    if worst is not None and tool in ("Read", "NotebookRead") and c is not None:
        try:
            from stop_guessing import handlers

            handler = handlers.find(ident.canonical_path, frozenset(c.labels), payload.get("cwd"))
        except Exception:  # noqa: BLE001 - a broken index must not take the call down
            handler = None
        if handler is not None:
            call["delegated_script"] = {"signed": False, "test_passed": None,
                                        "id": handler.id}
            artifact["has_handler"] = True

    ctx = state.context(posture=posture, call=call, artifact=artifact)
    d = ps.evaluate(_op_for(tool, call), ctx)

    # Authorised — NOW the handler may touch the artifact. A `forbid` means the handler never
    # runs at all, which is the difference between a control and a description of one.
    if handler is not None and d.outcome != "deny":
        try:
            from stop_guessing import handlers

            substitution = handlers.run(handler, ident.canonical_path)
        except Exception:  # noqa: BLE001 - a broken handler must not take the call down
            substitution = None
        if substitution is not None:
            call["delegated_script"]["test_passed"] = substitution.test_passed
            if not substitution.usable:
                artifact["has_handler"] = False

    # An `ask` under bypassPermissions overrides a decision the user has ALREADY made. The whole
    # meaning of that mode is "do not interrupt me", so re-prompting is not a control, it is a
    # tool ignoring its operator. The ask degrades to allow-with-warning; the custody record still
    # says an ask was warranted and why it did not fire, so nothing is lost from the evidence.
    #
    # A DENY is not degraded. Bypassing permission PROMPTS is not the same as bypassing policy,
    # and credential egress does not become acceptable because prompts are off.
    permission_mode = payload.get("permission_mode") or ""
    downgraded_from = None
    if d.outcome == "ask" and permission_mode in ("bypassPermissions", "acceptEdits"):
        downgraded_from = "ask"
        d = _downgrade_to_warning(d, permission_mode)

    from stop_guessing.taint import persist

    if worst is not None and d.outcome in ("allow", "ask"):
        # An `ask` that the human then approves still puts the bytes in context, so the taint is
        # recorded at the point of decision rather than waiting for an outcome we never see.
        state.touch(ArtifactRef(art_id, ident.canonical_path, ident.content_digest,
                                frozenset(c.labels)))
        persist.save(state)
    elif call["is_egress"] and d.outcome == "allow":
        state.egress()
        persist.save(state)

    # The operator's rule, exactly: if a permission prompt is pending, delegate is one of the
    # options; if none is pending, take the preferred path and say that is what happened.
    prompt_pending = (d.outcome == "ask" and downgraded_from is None)
    if substitution is not None and substitution.usable and not prompt_pending:
        return _substituted(payload, tool, substitution, artifact, ident, state, call,
                            posture, cache_agreed, d)

    reason = _render(d, artifact, state, path, downgraded_from=downgraded_from,
                     permission_mode=permission_mode)
    if substitution is not None and substitution.usable and prompt_pending:
        reason += _offer_delegate(substitution, substitution.script, ident.canonical_path)
    entry = _record_decision(payload, tool, d, artifact, ident, state, call,
                             posture, cache_agreed, downgraded_from=downgraded_from,
                             permission_mode=permission_mode)
    return {"outcome": d.outcome, "reason": reason,
            "determining_policy": d.determining_policy,
            "warning": downgraded_from is not None,
            "downgraded_from": downgraded_from,
            "record": entry,
            "basis": {"taint": sorted(state.labels), "taint_depth": state.depth,
                      "custody_digest": state.digest}}


def _record_decision(payload, tool, d, artifact, ident, state, call, posture, cache_agreed,
                     *, downgraded_from=None, permission_mode="", substitution=None):
    """Append the custody record for this decision, in the §7 predicate shape.

    The gate previously wrote a flat ad-hoc dict and never used `ledger.entry.CustodyRecord` — so
    the deployed path produced records that failed the project's OWN sufficiency measure: 0 of 4
    governance questions answerable, because none of the eight evidence regimes was populated.
    Another instance of #13: the builder existed and the deployed path did not use it.
    """
    from stop_guessing.ledger.entry import CustodyRecord, RecordInvalid

    op = _op_for(tool, call)
    used = []
    subjects = []
    if ident is not None:
        used.append({"artifact_id": ident.artifact_id, "path": ident.canonical_path,
                     "digest": ident.content_digest, "labels": artifact.get("labels") or [],
                     "role": "input"})
        subjects.append({
            "name": f"file://{ident.canonical_path}",
            "uri": f"file://{ident.canonical_path}",
            "digest": {"sha256": ident.content_digest or ""},
            "annotations": {
                "csa.coc/artifact_id": ident.artifact_id,
                "csa.coc/classification": artifact.get("labels") or [],
                "csa.coc/digest_scope": "absent" if ident.content_digest is None else "full",
                # #56: the spelling the caller used, when it differs from what it resolves to.
                # Recording only the canonical path would hide that a benign-looking name was the
                # one presented — an auditor needs to see the alias, not just the right answer.
                "csa.coc/aliases": artifact.get("aliases") or [],
                "csa.coc/requested_path": artifact.get("requested_path") or ident.canonical_path,
            },
        })

    gaps = [] if cache_agreed else ["state cache disagreed with the ledger; ledger won"]
    # #59: an unverifiable ledger is a critical condition, not a cache disagreement. Saying so in
    # the record is the difference between "we noticed" and "we assumed it was a first run".
    unverifiable = getattr(state, "unverifiable_reason", None)
    if unverifiable:
        gaps.append(
            f"AUTHORITATIVE LEDGER UNVERIFIABLE: {unverifiable}. Session state was NOT taken from "
            "the agent-writable cache; a maximally-tainted state was assumed instead."
        )
    for alias in artifact.get("aliases") or []:
        # An alias that only became classified once resolved is a finding in its own right: it is
        # the shape of an attempt to read a protected artifact under an unprotected name.
        gaps.append(
            f"path aliasing: {alias['given']} resolves to {alias['resolves_to']} and gained "
            f"{','.join(alias['labels_gained'])}"
        )
    if ident is not None and ident.content_digest is None:
        gaps.append("artifact content was not digested at decision time (PreToolUse budget)")
    session_id = str(payload.get("session_id") or "unknown")
    prompt_id = payload.get("prompt_id")

    try:
        stmt = CustodyRecord(
            op=op,
            agent_id=f"spiffe://local/claude-code/session/{session_id}/agent/main",
            runtime_action_id=str(payload.get("tool_use_id") or f"{op}:{_now()}"),
            operator={"identity": f"{os.environ.get('USER', 'unknown')}@{_host()}",
                      "uid": os.getuid(), "host": _host()},
            session_id=session_id,
            posture=posture,
            outcome=d.outcome,
            channel="hookSpecificOutput.permissionDecision",
            at=_now(),
            recorded_at=_now(),
            record_id=f"sg:{session_id}:{payload.get('tool_use_id') or op}",
            method_kind=("delegated-script" if substitution is not None else
                         "denied" if d.outcome == "deny" else "direct-model"),
            input_digest=_input_digest(payload),
            policy_set_digest=policies().digest,
            determining_policy=d.determining_policy,
            known_gaps=gaps,
            extra={
                "actor": {"acted_on_behalf_of": {
                    "prov_type": "prov:Person",
                    "human_id": f"local:{os.environ.get('USER', 'unknown')}",
                    "authority": "prompt", "prompt_id": prompt_id,
                    "delegation_depth": 0}},
                "authority": {
                    "permission_mode": permission_mode or None,
                    "capability": {
                        "grant_id": f"cap:{posture}", "granted_by": d.determining_policy,
                        "scope": [op]}},
                "action": {"method": substitution.to_record() if substitution else {},
                           "tool": {"name": tool, "source": payload.get("tool_source")},
                           "gen_ai": {"operation_name": "execute_tool", "tool_name": tool,
                                      "tool_call_id": payload.get("tool_use_id")}},
                "decision": {"reason": d.reason,
                             "downgraded_from": downgraded_from,
                             "basis": {
                    "taint_labels": sorted(state.labels), "taint_depth": state.depth,
                    "taint_sources": sorted(state.sources),
                    "session_custody_digest": state.digest,
                    "cache_agreed": cache_agreed,
                    "counterfactual": d.counterfactual}},
                "resources": {"used": used},
                "lifecycle": {"prompt_id": prompt_id, "cwd": payload.get("cwd"),
                              "transcript_path": payload.get("transcript_path")},
                # The algo is asked, not guessed. With a daemon the hook holds no key, so
                # `chain_key()` is None while the record is in fact keyed — guessing here made
                # the record UNDERSTATE its own strength, which is the same class of error as
                # overstating it: the record stopped describing reality.
                "verification": {"chain": {"algo": _chain_algo()},
                                 "recorder": {"writer": "hook_gate", "isolation_tier": 0}},
            },
        ).build(subjects=subjects)
    except RecordInvalid:
        return None

    # Through the recorder, not straight to the file. When a daemon is running the hook holds no
    # chain key and does not own the ledger; when it is not, the fallback records tier 0 and why.
    from stop_guessing.recorder import client

    cfg = Path(os.environ.get("CLAUDE_CONFIG_DIR") or os.path.expanduser("~/.claude"))
    tier, _why = client.isolation_tier(cfg)
    stmt["predicate"]["verification"]["recorder"] = {
        "writer": "cocd" if tier > 0 else "hook_gate", "isolation_tier": tier,
    }
    stmt["predicate"]["verification"]["strength"] = _strength_for(stmt["predicate"])
    out = client.append(cfg, {"op": op, "at": _now(),
                              "actor": "stop-guessing/hook_gate",
                              "severity": "warn" if d.outcome == "deny" else "info",
                              "statement": stmt,
                              # Flat mirrors, so a reader does not have to walk the predicate
                              # to answer the common questions.
                              "session_id": session_id,
                              "outcome": d.outcome,
                              "resources": {"used": used}},
                        fallback_key=chain_key())
    return out.ref


def _strength_for(pred: dict) -> str:
    from stop_guessing.ledger.entry import strength

    return strength(pred)


def _chain_algo() -> str:
    """What the ledger is ACTUALLY chained with, from whoever is doing the chaining."""
    from stop_guessing.recorder import client

    cfg = Path(os.environ.get("CLAUDE_CONFIG_DIR") or os.path.expanduser("~/.claude"))
    info = client.daemon_info(cfg)
    if info and info.get("ok"):
        return "hmac-sha256" if info.get("keyed") else "sha256"
    return "hmac-sha256" if chain_key() else "sha256"


def _host() -> str:
    import socket
    try:
        return socket.gethostname()
    except OSError:
        return "unknown"


def _input_digest(payload: dict) -> str:
    from stop_guessing.artifacts.digest import bytes_digest
    return "sha256:" + bytes_digest(
        json.dumps(payload.get("tool_input") or {}, sort_keys=True, default=str).encode())


NL = chr(10)


def _substituted(payload, tool, sub, artifact, ident, state, call, posture, cache_agreed, d):
    """The delegated answer, plus the record proving how it was obtained.

    Reached only when no permission prompt is pending. When the host WILL prompt, delegation is
    offered as one of the options instead — see `_offer_delegate`. The rule the operator gave:
    if a permission is required, delegate is a choice; if none is required, take it and say so.
    """
    from dataclasses import replace as _replace

    from stop_guessing.taint import persist
    from stop_guessing.taint.state import ArtifactRef

    # The handler's OUTPUT is what entered context, so the taint follows the read that produced
    # it. The file itself was never in context, which is the whole point.
    state.touch(ArtifactRef(ident.artifact_id, ident.canonical_path,
                            ident.content_digest, frozenset(artifact.get("labels") or [])))
    persist.save(state)

    decision = _replace(d, outcome="deny",
                        determining_policy="20-steer#delegated-script-permitted",
                        reason="handled by a tested deterministic handler")
    entry = _record_decision(payload, tool, decision, artifact, ident, state, call,
                             posture, cache_agreed, substitution=sub)

    labels = ",".join(artifact.get("labels") or [])

    # #53 (SG-HARD-020). CLAIM-10 says that under `bar` the model receives only a handle or a
    # summary. It was false in the deployed path: emit_for_model() existed, was proved, and was
    # called by nothing, while this text embedded the handler's ENTIRE output — and a hook decision
    # reason is shown to the model. A handler returning the file's contents therefore placed the
    # protected bytes in context while the record said delegated handling had occurred.
    #
    # The disclosure now follows the posture: `bar` gets handle+summary, everything else keeps the
    # full output it has always had. Under `bar` the whole point is that the bytes never arrive.
    from stop_guessing.delegate import emit_for_model

    emitted = emit_for_model(sub.output, "summary" if posture == "bar" else "full",
                             artifact_id=artifact.get("id") or "")
    if emitted["mode"] == "full":
        result_block = ["RESULT:", sub.output.rstrip()]
    else:
        result_block = [
            "RESULT (posture `bar` — the bytes are withheld by design, not by failure):",
            f"  handle : {emitted['handle']}",
            f"  size   : {emitted['lines']} line(s), {emitted['bytes']} byte(s)",
            f"  digest : {emitted['digest'][:32]}",
            f"  shape  : {emitted.get('first_line_shape', '')}",
            "",
            "Pass the handle to a delegated script to work with this without reading it.",
        ]

    lines = [
        f"CHAIN-OF-CUSTODY [delegated]: {ident.canonical_path} is classified {labels}.",
        "",
        f"No permission prompt was pending, so the preferred path was taken automatically: "
        f"{Path(sub.script).name} handled it and the file was not read into context.",
        "",
        *result_block,
        "",
        f"That answers the request. Handler test passed, digest "
        f"{(sub.script_digest or '')[:16]}, recorded {entry}.",
        "",
        "If you need something the handler does not return, extend it and re-run:",
        f"  stop-guessing run {sub.script} --artifact {ident.canonical_path}",
    ]
    return {"outcome": "deny", "reason": NL.join(lines), "delegated": True,
            "determining_policy": decision.determining_policy,
            "record": entry,
            "basis": {"taint": sorted(state.labels), "taint_depth": state.depth,
                      "custody_digest": state.digest}}


def _offer_delegate(sub, handler_script: str, artifact_path: str) -> str:
    """The delegate option, phrased for an ask the human is actually going to answer."""
    return NL.join([
        "",
        "A tested handler exists for this artifact and can answer without the contents entering "
        "context:",
        f"  {Path(handler_script).name}",
        "",
        "Approving this call reads the file directly. To use the handler instead, run:",
        f"  stop-guessing run {handler_script} --artifact {artifact_path}",
    ])


def _downgrade_to_warning(d, permission_mode: str):
    """Turn an ask into an allow, keeping the reason so it can be shown as a warning."""
    from dataclasses import replace as _replace

    return _replace(
        d, outcome="allow",
        reason=d.reason,
        counterfactual=(f"would have asked, but permission_mode={permission_mode} is a standing "
                        "decision not to be interrupted; recorded as a warning instead"),
    )


def _protect_ledger() -> bool:
    """Whether the ledger deny-list is active. Project config may turn it ON, never OFF (#47).

    SG-HARD-013: the project file could set protect_ledger=false, and a project file is writable
    by the party being recorded. Combined with a posture downgrade that let the recorded agent
    switch off the protection on its own evidence and then modify it — the one capability this
    tool exists to deny.

    The switch stays real, because a genuine operator may not want even this refusal. It just has
    to be set somewhere the recorded party does not control: `managed.json` in the profile.
    Precedence is managed, then profile, then project — and the project layer is honoured only
    when it TIGHTENS.
    """
    import json as _json

    cfg = Path(os.environ.get("CLAUDE_CONFIG_DIR") or os.path.expanduser("~/.claude"))

    def _read(path):
        try:
            return _json.loads(Path(path).read_text(encoding="utf-8")).get("protect_ledger")
        except (OSError, ValueError):
            return None

    managed = _read(cfg / "managed.json")
    if isinstance(managed, bool):
        return managed

    profile = _read(cfg / "stop-guessing.json")
    if isinstance(profile, bool):
        return profile

    project = _read(Path.cwd() / ".stop-guessing.json")
    if project is True:
        return True          # tightening from the default is fine
    if project is False:
        # Refusing to loosen is itself worth recording: someone tried.
        return True
    return True


def _op_for(tool: str, call: dict) -> str:
    if call["is_egress"]:
        return "artifact.egress"
    if call["is_write"]:
        return "artifact.write"
    return "artifact.read"


def _render(d, artifact: dict, state: SessionCustodyState, path: str,
            *, downgraded_from=None, permission_mode="") -> str:
    if downgraded_from:
        head = (f"CHAIN-OF-CUSTODY [warning]: {d.reason}\n\n"
                f"Allowed without asking because permission_mode={permission_mode}. "
                "This is recorded as an ISO 27037 alteration and raises session taint, "
                "which may deny an egress later in this session.")
        return head + f"\n\n[{d.determining_policy} — ask downgraded to warning]"
    head = f"CHAIN-OF-CUSTODY [{d.outcome}]: {d.reason}".strip()
    lines = [head]
    if artifact.get("classified") and path:
        lines.append(f"\n{path} is classified {','.join(artifact['labels'])}.")
    if d.guidance == "delegate" and artifact.get("has_handler"):
        lines.append(
            "\nPreferred — delegate:\n"
            f"  stop-guessing delegate new --artifact {artifact.get('id', '')} "
            '--intent "<what you actually need>"\n'
            "Scaffolds the script and its test, runs the test, and on green runs the script under "
            "a recorded capability. You receive the script's OUTPUT and a handle — not the file.\n\n"
            "Proceeding directly is allowed and is recorded as an ISO 27037 alteration; it also "
            "raises session taint, which will deny egress later in this session."
        )
    if d.outcome == "deny" and state.sources:
        lines.append(f"\nContributing artifacts: {', '.join(sorted(state.sources))}")
        lines.append(f"Session custody digest: {state.digest[:16]}…")
    lines.append(f"\n[{d.determining_policy}]")
    return "\n".join(lines)
