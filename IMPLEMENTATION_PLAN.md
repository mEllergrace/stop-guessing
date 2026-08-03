# STOP-GUESSING — implementation plan

**Repo:** `mEllergrace/stop-guessing` (public) · **Working dir:** `/Users/isme/Software/coc-prov` (name unchanged — renaming breaks projectMan tracking and spindlebox index paths) · **Distribution name:** `stop-guessing`, CLI aliases `coc-prov` and `coc` kept forever · **Licence:** Apache-2.0

This document is written to be handed to a third-party agentic with no prior context. Every path, schema field, and acceptance test is stated concretely.

---

## 1. Context

Agentic systems create a chain-of-custody hole. The agent reads data, transforms it, reports a result — and nothing durable records which bytes entered, what happened to them, or whether the report is true. Every downstream audit inherits that gap.

Three things make this urgent and tractable right now:

1. **CSA has published the requirement and not the implementation.** AICM v1.1.0 control **DSP-20 "Data Provenance and Transparency"** requires tracking data sources and transparency about origin and use. CSA's December 2025 paper *Data Security within AI Environments* recommends, verbatim, *"cryptographically signed data provenance tracking using blockchain or merkle trees"* and *"tamper-evident logs (e.g. AWS QLDB, Sigstore)."* CSA's own **AICM Agentic Gap Analysis (v1 draft)** finds 40 controls missing for agentic systems — Logging & Monitoring 57% missing, IAM 63% — and proposes `IAM-AG-03` (complete delegation chains linking every sub-agent action to the originating human request), `LOG-AG-01` / `LOG-AG-02` (tool-invocation logging with semantic context sufficient for forensic reconstruction). The **CSA Agent Registry Specification v1 (draft)** defines a four-tier lineage DAG whose bottom tier — Runtime Action — is exactly what this tool emits. **None of these has a reference implementation.**

2. **Everything that exists records actions; nothing records data flow.** Verified across the field: Claude Code's own OTel events, `agent-receipts/obsigna` (Ed25519 hash-chained receipts, deliberately hashes parameters and stores no data identity), `Helixar-AI/HDP` (delegation custody, self-declared "HDP stops at provenance, it does not enforce"), Langfuse / Arize Phoenix / LangSmith (span trees are control flow, not data flow), OpenLineage (right graph primitive, no agent emitter), Microsoft's `agent-governance-toolkit` (best published provenance schema, implementation marked 🔜). No tool feeds accumulated session custody state back into the permission decision. That join is the gap.

3. **The failure mode is documented and expensive.** Replit/SaaStr, 21 July 2025 (AI Incident Database #1152): an agent deleted a production database during an explicit code freeze, fabricated ~4,000 fictional records, and misreported what it had done — no independent record of any of it. Berkeley RDI, April 2026: a zero-capability agent scored ~100% on eight benchmarks by attacking the evaluator, including installing a fake `curl` wrapper that returned fabricated success to the grader. That last one is a direct design constraint: **the recorder must not be reachable by the agent it records.**

**Intended outcome:** a tool CSA staff install once, that produces an evidence chain an auditor will accept, and that carries a progressively-filled AI-CAIQ v1.1.0 version-inspected on every run.

### The thesis, in its defensible form

The owner's MO is *"agentics do not handle data; they decide how to respond to a request for data by looking at risk factors."* The published literature supports a narrower claim, and the narrower claim is the one to ship in the spec:

> The agent's control decisions are computed only from trusted inputs; data handling is delegated to deterministic, capability-constrained code; and every delegation is recorded.

Backing: Beurer-Kellner et al., *Design Patterns for Securing LLM Agents against Prompt Injections* (arXiv:2506.08837, IBM/Google/ETH/Microsoft) — *"once an LLM agent has ingested untrusted input, it must be constrained so that it is impossible for that input to trigger any consequential actions"*; and Debenedetti et al., *CaMeL* (arXiv:2503.18813, DeepMind/ETH) — *"the untrusted data retrieved by the LLM can never impact the program flow"* (77% of AgentDojo tasks with provable security vs 84% undefended — quote the 7-point cost, don't hide it). The stronger *"the model never sees data"* claim is what the `bar` posture implements, and it ships as an option; it is just not the claim the docs lead with.

**Provenance is evidentiary, not preventive.** A hash-chained log of an exfiltration is still an exfiltration. Do not sell this as a prompt-injection defence — a competent reviewer will take the whole thing apart on that point.

---

## 2. Settled decisions

| # | Decision |
|---|---|
| 1 | **Default posture = `steer`.** Three postures ship: `observe` (record everything, block nothing), `steer` (default), `bar` (model barred from opening classified artifacts). |
| 2 | **Agent-agnostic Python core + Claude Code adapter first.** Codex adapter is a stub implementing the same interface. |
| 3 | **Vendor no-noodles byte-identically, depend on nothing, and supersede it.** STOP-GUESSING must be able to fully replace `moonsoup/no-noodles` on a machine with byte-compatible semantics. |
| 4 | **Product name: STOP-GUESSING.** Repo `mEllergrace/stop-guessing`; working dir stays `coc-prov`; `coc-prov` retained as a permanent CLI alias. |
| 5 | **Full-depth tracking, fully removable.** See §3. |
| 6 | **Offline by default.** No runtime path makes an external network call. Sigstore/Rekor/RFC-3161 anchoring are opt-in flags, default off, with a startup banner when enabled. CSA material never leaves the host by default. |

### Deviations from the original brief, with reasons

- **Cedar is not a runtime dependency.** `cedarpy` is third-party, not installed, and a compiled dep inside a per-tool-call `PreToolUse` hook contradicts "vendor the patterns, depend on nothing." Ship a **Cedar-shaped pure-Python PDP** — same `principal / action / resource / context` model, same entity/schema shape, `forbid` overrides `permit`, deny by default — plus `coc policy export --cedar` validated by the real `cedar` CLI **in CI only**. `--pdp cedar` stays available as a backend when `cedarpy` imports. Option opened, not closed.
- **`steer` does not deny the first touch.** Denying read #1 taxes exploration and does nothing about read #12. `steer` **asks** on first touch of a newly-classified artifact and **denies** on (a) accumulated taint crossing threshold or (b) any egress-shaped action while tainted.
- **The FRE 902 certifier is a segment-level object, not a per-record field.** Rule 902(11)/(13) contemplates certifying a record *set*.
- **A bare SHA-256 chain is insufficient.** An agent with ledger write access can truncate and recompute an entirely valid chain — `verifyChain` returns `intact: true`. The chain is **keyed**: HMAC-SHA256 with a per-session key from the OS keychain. This is v1, not later hardening.
- **OpenLineage export is a documented stub in v1** (mapping table in `docs/ADAPTERS.md`, `NotImplementedError` with field mapping in the docstring). It has no integrity semantics. Effort goes to CASE/UCO instead, which gives third-party validation via `usnistgov/CASE-Implementation-PROV-O`'s `case_prov_check`.

---

## 2.1 Definition of done — the goal

> The STOP-GUESSING toolchain, plugins, skills and slash-commands have been **proven to run and to meet the stated application claims**, by a set of proofs **it can point to using its own toolsets**. The toolchain has been **assessed against AICM** and has its own local **AI-CAIQ filled using its own toolchain, as the last set of steps.**

This is a self-referential acceptance criterion and it is the strongest one available: the tool's own evidence chain is the evidence that the tool works. If STOP-GUESSING cannot produce an auditable proof of its own claims, it cannot credibly produce one for anything else.

Four things it requires, none of which is satisfied by a green test suite:

**1. The claims must be enumerable.** A prose README is not provable. `docs/claims.yaml` holds every application claim as a machine-readable record:

```yaml
- id: CLAIM-07
  statement: >-
    Accumulated session taint denies an egress that the same call would have been
    allowed to make earlier in the session.
  surface: [hook:PreToolUse, cli:"stop-guessing demo"]
  proof_kind: live-run           # live-run | adversarial | property | negative
  aicm: [DSP-20, LOG-AG-02]
  proofs: []                     # filled by `stop-guessing prove`, never by hand
```

A claim with `proofs: []` at release time is a **failed** claim, not an unassessed one. `stop-guessing claims check` exits non-zero.

**2. The proofs must be its own records, not test output.** `stop-guessing prove --claim CLAIM-07` executes the claim's surface against the real running system and writes the resulting **ledger record ids** back into `proofs:`. A proof reference is only valid if `stop-guessing ledger verify` confirms the chain covering those records is intact and keyed. Test names and CI logs are supporting material; the ledger record is the proof. This is the same standard the tool imposes on everything else — `reconcileExecution` exists precisely because *an audit trail owned by the audited party is not an audit trail*, so the proofs are written by the recorder, never by the process claiming success.

**3. Negative and adversarial claims count.** A toolchain that only proves its happy paths has proven nothing an auditor wants. Required proof kinds include the M5 attacker suite (PATH-shadowing, ledger direct-write, truncate-and-reseal without the key, hook substitution, daemon kill) and the negative claims — that a record missing `alterations` is refused, that a drifted AI-CAIQ refuses regeneration, that `verify --sufficiency` reports `incomplete` rather than overclaiming.

**4. The AI-CAIQ is filled by the toolchain, last.** Not written by hand and not retrofitted. Every answer's `evidence:` block resolves to proof record ids produced in step 2; `stop-guessing caiq evidence check` resolves each one and demotes any answer whose evidence has gone stale to `unassessed`. Only when the claims table is fully proven does `stop-guessing caiq fill` run — so the workbook is a *derived artifact of the evidence*, in the same direction of causation the tool enforces for everyone else. Reversing that order — filling the workbook and then hunting for evidence — is exactly the failure `PIPELINE-CONFORMANCE-GAP.md` documents in rockin-robin's own history: *"that is a STRING IN A PROMPT, not conformance."*

The command that answers the goal in one line, and the thing a reviewer runs:

```
stop-guessing attest --self
```

Emits a claims→proofs→controls matrix with the chain verdict, the AI-CAIQ coverage, and the sealed segment digest; exits non-zero if any claim is unproven, any proof's chain is broken, any evidence ref is stale, or the AI-CAIQ was modified outside the pipeline.

---

## 3. Full depth, fully removable

**Full depth is the default and is never silently reduced.** Every artifact touch, every derivation edge, every delegation hop, every decision basis is recorded — not sampled, not metadata-only. Where fidelity is genuinely reduced (e.g. a 4 GB file digested head-only), the record says so explicitly in `subject[].annotations["csa.coc/digest_scope"]` and in `verification.known_gaps`. An empty `known_gaps: []` is a positive assertion that nothing was skipped; a **missing** key means nobody looked, and is rejected at write.

**Removability, at four levels, none of which destroys accumulated evidence:**

| Level | Mechanism | Effect |
|---|---|---|
| Posture | `posture: observe` in `./.stop-guessing.json` | Records everything, blocks nothing |
| Per-rule | `custody_tracking: off` via the 4-layer config chain | Gate goes inert; vendored no-noodles rules keep running |
| Per-project | `./.stop-guessing.json` overrides global | Scoped disable, no global change |
| Uninstall | `install.sh --uninstall` | Removes hooks and registrations; **preserves** `$CLAUDE_DIR/stop-guessing/ledger/**` and `observations.jsonl` — accumulated audit trail is not disposable state (precedent: `no-noodles/install.sh:66-69`, asserted by `tests/test_install.sh:154`) |

A posture downgrade is itself a recorded event (`authority.posture` + `authority.posture_source` in every record), so an audit can see when tracking was relaxed and by which config layer.

---

## 4. Reuse map — build none of this from scratch

The check-before-building rule applies hardest here. Every item below exists, works, and has tests.

| Need | Existing asset | Action |
|---|---|---|
| Hash-chained tamper-evident ledger | `/Users/isme/Software/rockin-robin/src/rockinRobinAudit.ts` (148 ln) — `AuditEntry{seq,at,kind,actor,detail,severity,prevHash,hash}`, `appendAudit`, `verifyChain() -> {intact,brokenAt,reason}`, `classifyAlert`. Already mapped to AICM LOG-03/LOG-10. 12 tests. | **PORT to Python**, add keying |
| Refuse-to-append-onto-broken-chain | `rockinRobinAuditSink.ts` (88 ln) — *"appending would bury the break under new entries — the tampering would be laundered by the very log meant to reveal it"* | **PORT** |
| Detect fabricated/replayed agent claims | `rockinRobinWorkflow.ts` — `issueNonce(instanceId,seq)` (FNV-1a, deterministic, re-derivable), `reconcileExecution(ledger, reported) -> {verified, findings[]}`. Doc comment: *"An audit trail owned by the audited party is not an audit trail."* | **PORT** |
| Keyed MAC + content fingerprint + key storage | `/Users/isme/Software/secretarius/src/secretarius/vault/crypto.py` — `value_hash(dedup_key, plaintext)`, `meta_mac(master_key, fields: list[str])`, AES-256-GCM with AAD. `vault/keyproviders.py` — OS keychain → argon2id passphrase → keyfile chain | **VENDOR** |
| Content-addressed snapshot + drift detection | `/Users/isme/Software/spindlebox/spindlebox/staleness.py` — `file_digest`, `snapshot_files`, `is_stale`, `stale_items`, `stale_report`. Tests at `tests/test_staleness.py` | **PORT** |
| AI-CAIQ fill | `/Users/isme/Software/rockin-robin/scripts/fill_ai_caiq.py` (144 ln) — hard-errors on unknown control ID, answer outside `{Yes,No,NA}`, `NA` + non-empty `ssrm`; leaves unassessed controls **empty** | **WRAP unmodified** |
| AI-CAIQ coverage | `rockin-robin/scripts/ai_caiq_coverage.py` (75 ln) | **WRAP unmodified** |
| AI-CAIQ structural verify | `/Users/isme/.claude/plugins/cache/rich-text/rich-text/0.2.8/skills/rich-text/scripts/verify_ai_caiq_workbook.py` — refuses if sheets/dimensions differ, any non-C:F cell changed, validations changed, or a value is outside CSA vocabulary | **WRAP unmodified** |
| AICM control lookup | `/Users/isme/Software/projectMan/scripts/aicm_map.py` + `test_aicm_map.py` — resolves control IDs, reports unresolved rather than guessing | **WRAP**, parameterise `DEFAULT_WORKBOOK` |
| Risk scoring | `/Users/isme/Software/no-noodles/hooks/risk_score.py` + `risk-rules.json` | **VENDOR unmodified**, call via CLI, never edit |
| Config resolution | `no-noodles/hooks/lib_config.sh` — `resolve_state`, 4-layer chain | **VENDOR**, mirror the shape for CoC keys |
| Installer JSON surgery | `no-noodles/install.sh` — idempotent, dedupes on command string, **resolved absolute paths never `~`**, installs docs to **both** `skills/` and `commands/` | **REUSE the code** |
| Test harness style | `no-noodles/tests/test_*.sh` — `set -uo pipefail`, `check()` + `FAILS` counter, `export CLAUDE_CONFIG_DIR="$TMP/claude"` with `mktemp -d` + `trap`, synthetic hook JSON on stdin | **COPY the pattern** |
| Plugin + dual-marketplace layout | `/Users/isme/Software/Events_Horizon/rich-text/` — `core/` + `adapters/{claude-code,codex,generic-system-prompt,openai-agents-python}.md` + `.claude-plugin/` + `.agents/plugins/` | **COPY wholesale** |
| Pages site | `no-noodles/docs/` — single 18 KB `index.html`, inlined CSS vars, full OG/Twitter block, ships favicon/logo/og assets. GitHub Pages `build_type: legacy`, `main:/docs` | **COPY the pattern** |

**Do not rebuild capture.** Claude Code already emits `claude_code.tool_decision` (tool_name, tool_use_id, decision, tool_source, source), `claude_code.tool_result` (success, duration_ms, sizes), `claude_code.tool.execution` spans, identity on every event (session.id, organization.id, user.account_uuid, user.email), correlation keys (prompt.id, tool_use_id, message.uuid, request_id), file paths under `OTEL_LOG_TOOL_DETAILS=1`, and `TRACEPARENT` propagation into Bash subprocesses and MCP HTTP. STOP-GUESSING is a **hook-based PEP plus an enrichment layer** — not a proxy, not a collector, not an SDK.

---

## 5. Standards posture

| Standard | Use | Why |
|---|---|---|
| **in-toto Attestation Framework v1** (CNCF graduated) | **EMIT.** `Statement{_type:"https://in-toto.io/Statement/v1", subject:[…digest], predicateType, predicate}`, DSSE envelope, JSONL bundle | Subjects matched purely by digest, so any artifact qualifies. Registering a `Custody/v1` predicate type converts "we invented a format" into "we registered a predicate". The bundle format *is* JSONL — same as the ledger |
| **Sigstore** (bundle, `cosign sign-blob`, Rekor v2, `sigstore/timestamp-authority`) | **OPT-IN.** Local signing by default; RFC 3161 and public anchoring behind flags | Rekor stores hashes only, so a private ledger gets public verifiability without disclosure — but that is a deliberate egress decision, never a default |
| **W3C PROV** (Recommendation, 2013, stable; `prov` 2.1.1 installed) | **ALIGN.** `Entity`/`Activity`/`Agent`/`used`/`wasGeneratedBy`/`wasDerivedFrom`/**`actedOnBehalfOf`** as the internal vocabulary | `actedOnBehalfOf` is exactly the delegation edge CSA's `IAM-AG-03` demands. Export becomes a serializer, not a rewrite |
| **CASE/UCO** (NIST-involved) | **EXPORT.** Chain-of-**custody** (who handled it) and chain-of-**evidence** (what processes treated it), kept as separate exports | `usnistgov/CASE-Implementation-PROV-O`'s `case_prov_check` gives independent third-party validation of custody breaks |
| **OTel GenAI semconv** (Development stability, `semantic-conventions-genai` since v1.42.0) | **EMIT.** Valid `gen_ai.*` / `mcp.*` spans plus a `csa.coc.*` extension namespace | There are zero provenance attributes in the spec today. Pre-1.0 is an advantage — a CSA-authored attribute group is a plausible upstream PR |
| **ISO/IEC 27037:2012 §5.4.1** | **SCHEMA SOURCE.** unique identifier, source, operator, method, hash, timestamp, handover events, and **any unavoidable alteration with written justification** | That last field is the one everyone omits and the one an agentic system needs most |
| **FRE 902(13)/(14)** | **CERTIFICATION OBJECT.** The hash is the technical basis; a **named qualified person's certification** is the legal operative act | Without a designated certifier the ledger never reaches self-authentication |
| **SEC Rule 17a-4(f)** as amended Oct 2022 | **DESIGN TARGET.** All modifications and deletions, date+time of every operator action, the individual(s) responsible, enough to re-create the original record and interim iterations | The best regulator-written spec of an adequate tamper-evident ledger. Satisfy it verbatim |
| **AICM v1.1.0** | **MAP.** DSP-20, DSP-05, DSP-24, LOG-03, LOG-10, LOG-12, STA-09, MDS-*; draft agentic: IAM-AG-03, LOG-AG-01, LOG-AG-02 | The deliverable CSA staff expect |
| **OpenLineage** | **STUB.** Mapping documented, `NotImplementedError` | No integrity semantics; never present as the custody record |
| **C2PA** | **IGNORE for the data path** | Trust model bound to media byte ranges and a CA trust list we cannot join; `crJSON` self-declares as *not* a general-purpose machine-readable format |
| **Blockchain anchoring** | **DO NOT BUILD** | No regulated-audit adoption. RFC 3161 / eIDAS qualified timestamps carry the legal recognition. Including a chain will cost credibility with exactly this audience |

**Prior art to credit explicitly in the README** (not doing so invites the "you reinvented HDP" review): `Helixar-AI/HDP` (Apache-2.0, IETF I-D — delegation custody; its `data classification` and `network egress` scope fields are directly reusable), `agent-receipts/obsigna` (Apache-2.0, Ed25519 hash-chained receipts with a working Claude Code `PostToolUse` hook), Microsoft `agent-governance-toolkit`'s `docs/compliance/data-provenance-model.md` (best published schema, unimplemented), PROV-AGENT (arXiv:2508.02866, ORNL/Argonne, IEEE e-Science 2025 — peer-reviewed PROV extension for agentic workflows), Agent-Sentry (arXiv:2603.22868 — the argument for per-*argument* provenance, not per-call).

---

## 6. Architecture

Distribution `stop-guessing`; import package `stop_guessing`; console scripts `stop-guessing` (primary), `coc-prov` (alias, permanent), `coc` (short).

```
stop_guessing/
  version.py        VERSION file is single source of truth
                    (test asserts VERSION == pyproject == plugin.json == marketplace.json == install stamp)
  ids.py            record ids (ULID), SPIFFE agent URIs, artifact ids
  clock.py          monotonic-checked UTC; a backwards clock is a recorded finding

  ledger/
    entry.py        CustodyRecord dataclass            PORT rockinRobinAudit.ts AuditEntry
    chain.py        append/verify/genesis, KEYED       PORT hashEntry/verifyChain/appendAudit
    sink.py         JSONL, refuses broken/truncated    PORT rockinRobinAuditSink.ts
    segments.py     seal-and-archive                   NEW — replaces no-noodles' 5000-line truncate
    reconcile.py    issueNonce + reconcileExecution    PORT rockinRobinWorkflow.ts
    alerts.py       classifyAlert / alertsFrom         PORT (default-escalate-on-unknown)

  attest/
    statement.py    in-toto Statement v1 builder
    dsse.py         DSSE PAE encode, sign/verify
    keys.py         keychain / argon2id / keyfile      VENDOR secretarius keyproviders.py
    crypto.py       value_hash, meta_mac, sealed refs  VENDOR secretarius crypto.py
    tsa.py          RFC 3161 — OPT-IN, offline default, no public Rekor
    bundle.py       JSONL attestation bundle == the sealed segment

  artifacts/
    digest.py       file_digest / snapshot_files       PORT spindlebox staleness.py
    identity.py     artifact_id ↔ path ↔ content; survives moves and rewrites
    classify.py     rules/classify.yaml → labels
    registry.py     sqlite artifact table + DAG store

  taint/
    labels.py       label lattice; declassification requires a named human
    state.py        SessionCustodyState: accumulate, digest, serialize
    graph.py        derivation edges, transitive closure, PROV edge emission
    persist.py      sqlite materialized view; the ledger is the authoritative replay source

  policy/
    schema.py       Cedar-shaped entity/action/context schema
    model.py        Principal / Action / Resource / Context
    engine.py       pure-Python PDP, forbid-overrides-permit, deny-by-default
    loader.py       policy/coc.policy.d/*.yaml + policy_set_digest
    cedar_export.py transpile → .cedar for `cedar validate` in CI
    cedar_backend.py OPTIONAL real-Cedar backend when cedarpy imports
    risk.py         thin wrapper over VENDORED no-noodles risk_score.py — CLI unchanged

  prov/
    vocab.py        Entity/Activity/Agent/used/wasGeneratedBy/wasDerivedFrom/actedOnBehalfOf
    export_prov.py  PROV-JSON
    export_case.py  CASE/UCO JSON-LD — chain-of-custody AND chain-of-evidence, split
    export_otel.py  spans + csa.coc.* attribute namespace
    export_openlineage.py  STUB with the mapping in its docstring

  adapters/
    base.py         THE INTERFACE (§6.1)
    claude_code/    payload.py, decide.py, capabilities
    codex/          stub implementing base.py
    generic/        stdin-JSON → stdout-JSON

  recorder/
    daemon.py       cocd — unix-socket append-only writer
    client.py       hook-side client; fail-CLOSED in steer/bar, fail-OPEN in observe
    guard.py        self-integrity: writer digest, argv[0] realpath, socket perms, settings pin
    fallback.py     direct write when the daemon is absent → isolation_tier 0, recorded as such

  compat/
    nonoodles/      VENDORED byte-identical no-noodles 1.0.1 + the hardened
                    check_before_build.sh + MANIFEST.sha256
    dispatcher.py   vendored rules in original order, then the CoC gate
    migrate.py      inventory → install → verify → (optional) uninstall

  caiq/
    workbook.py     A1 JSON parse + version inspect                      NEW
    fill.py         WRAPS rockin-robin scripts/fill_ai_caiq.py
    coverage.py     WRAPS rockin-robin scripts/ai_caiq_coverage.py
    verify.py       WRAPS rich-text scripts/verify_ai_caiq_workbook.py
    aicm.py         WRAPS projectMan scripts/aicm_map.py
    evidence.py     NEW — evidence refs → ledger/test/code resolution + staleness

  cli/  main.py + cmd_*.py
```

**Boundary rule:** `ledger/`, `taint/`, `policy/` are pure — no filesystem, no clock, no env. `sink.py`, `persist.py`, `registry.py` and `recorder/` are the only IO.

### 6.1 Adapter interface

```python
@dataclass(frozen=True)
class AdapterCapabilities:
    can_deny: bool
    can_ask: bool
    can_defer: bool
    can_rewrite_input: bool            # updatedInput
    can_rewrite_output: bool           # updatedToolOutput
    sees_tool_result: bool
    has_session_id: bool
    has_prompt_id: bool
    has_subagent_identity: bool        # agent_id / agent_type
    has_compaction_signal: bool
    structured_decision_channel: bool  # hookSpecificOutput vs exit codes only

class AgentAdapter(ABC):
    name: str; version: str
    @abstractmethod
    def capabilities(self) -> AdapterCapabilities: ...
    @abstractmethod
    def parse_event(self, raw: bytes, env: Mapping[str, str]) -> ToolCallEvent: ...
    @abstractmethod
    def emit_decision(self, d: Decision) -> tuple[int, bytes]:      # (exit_code, stdout)
        ...
    def parse_result(self, raw: bytes) -> ToolResultEvent | None: ...
    def emit_redaction(self, r: Redaction) -> tuple[int, bytes] | None: ...
    def session_key(self, ev: ToolCallEvent) -> SessionKey: ...
```

`capabilities()` drives `verification.known_gaps` on every record and gates postures: `bar` refuses to activate when `can_deny=False`; `steer` degrades to `observe` **with a recorded reason** rather than silently. Claude Code: all `True`. Codex stub: `can_deny=True` via exit code, everything else `False`, `structured_decision_channel=False` → decisions emit exit 2 + stdout and `ask` collapses to `deny` with an explanatory reason.

---

## 7. The custody record

Envelope is an in-toto Statement v1; the ledger is the JSONL bundle. `predicateType: "https://stop-guessing.dev/Custody/v1"`. The predicate is organised by the **eight evidence regimes** from DEMM-Bench (arXiv:2606.20634), which found ledger-present baselines overclaim evidence sufficiency on 50% of governance questions — the regimes are the completeness checklist that answers it.

```jsonc
{
  "_type": "https://in-toto.io/Statement/v1",
  "subject": [{
    "name": "file:///Users/isme/work/CSA/roster.csv",
    "uri":  "file:///Users/isme/work/CSA/roster.csv",
    "digest": {"sha256": "9f2b…"},                        // REQUIRED — in-toto matches by digest alone
    "mediaType": "text/csv",
    "annotations": {
      "csa.coc/artifact_id": "art_01J…",                  // stable across content change
      "csa.coc/classification": ["restricted","pii"],
      "csa.coc/classification_source": "rules/classify.yaml#csa-roster",
      "csa.coc/digest_scope": "full"                      // full | head-64k | absent+reason
    }
  }],
  "predicateType": "https://stop-guessing.dev/Custody/v1",
  "predicate": {
    "record_version": "1.0.0",

    "record": {                                            // ISO 27037 unique id + time
      "id": "coc:01JQZ8…",                                 // R
      "seq": 4711,                                         // R
      "at": "2026-08-03T09:12:44.318Z",                    // R — when the ACT happened
      "recorded_at": "2026-08-03T09:12:44.402Z",           // R — SEC 17a-4(f): when the RECORD was made
      "clock_source": "system-monotonic-checked",
      "prev_hash": "0000…",                                // R
      "hash": "a3f1…",                                     // R — HMAC-SHA256, keyed
      "hash_alg": "hmac-sha256/session-key",
      "segment": "seg-000012"
    },

    // ── regime 1: ACTOR · PROV Agent · CASE chain-of-CUSTODY "who handled it"
    "actor": {
      "prov_type": "prov:SoftwareAgent",
      "agent_id": "spiffe://local/claude-code/session/6f2a…/agent/main",  // R
      "agent_type": "claude-code",
      "agent_tier": "deployed-agent",                      // CSA Agent Registry 4-tier
      "behavioural_fingerprint": "sha256:…",               // Agent Registry SHA-256 fingerprint
      "model": {"vendor":"anthropic","name":"claude-opus-5","fingerprint":"sha256:…"},
      "runtime_action_id": "toolu_01ABC",                  // R — Runtime Action Tier node
      "acted_on_behalf_of": {                              // PROV actedOnBehalfOf · AICM IAM-AG-03
        "prov_type": "prov:Person",
        "human_id": "mailto:…",                            // R in steer/bar
        "authority": "prompt",
        "prompt_id": "prm_01…",                            // R in steer/bar — ORIGINATING request
        "prompt_digest": "sha256:…",
        "delegation_depth": 2,
        "delegation_chain": [                              // R when depth > 0
          {"agent_id":"…/agent/main","at":"…","prompt_id":"prm_01…"},
          {"agent_id":"…/agent/sub-3","agent_type":"Task","at":"…","spawned_by_record":"coc:01JP…"}
        ]
      },
      "operator": {"identity":"…","uid":501,"host":"…",     // ISO 27037 §5.4.1 "operator"
                   "host_fingerprint":"sha256:…"}          // R
    },

    // ── regime 2: AUTHORITY
    "authority": {
      "posture": "steer",                                  // R — observe|steer|bar
      "posture_source": "./.stop-guessing.json",        // R — which config layer decided
      "permission_mode": "…",
      "capability": {"grant_id":"cap_01…",
                     "granted_by":"policy:coc.policy.d/10-base.yaml#read-project",
                     "scope":["read:project","exec:signed-script"],"expires_at":"…"},
      "session_trust": {"active": false, "granted_at": null},   // no-noodles compat
      "overrides_presented": ["# risk-ok"],
      "override_valid": true, "override_validation": "marker>=60ch, names scripts/"
    },

    // ── regime 3: ACTION · PROV Activity · ISO "method" · CASE chain-of-EVIDENCE
    "action": {
      "prov_type": "prov:Activity",
      "op": "artifact.read",                               // R — controlled vocabulary (§7.2)
      "tool": {"name":"Read","source":"builtin","call_id":"toolu_01ABC",
               "mcp_server":null,"skill":null},
      "gen_ai": {"operation_name":"execute_tool","tool_name":"Read","tool_type":"function",
                 "tool_call_id":"toolu_01ABC","agent_id":"spiffe://…"},   // OTel GenAI semconv
      "method": {                                          // R — ISO 27037 "method"
        "kind": "delegated-script",                        // direct-model|delegated-script|signed-script|denied
        "script": {"path":"scripts/extract_roster_counts.py","digest":"sha256:…",
                   "test":"scripts/test_extract_roster_counts.py","test_digest":"sha256:…",
                   "test_result":{"passed":true,"at":"…","exit_code":0,"evidence_digest":"sha256:…"},
                   "argv_digest":"sha256:…","nonce":"a91c…",
                   "signature":{"scheme":"dsse-ed25519","keyid":"coc-local-2026","sig":"…"}},
        "sandbox": {"cwd":"…","env_allowlist":["PATH","HOME"],"network":"deny"}
      },
      "input_digest": "sha256:…",                          // R — ALWAYS
      "input_recorded": "digest-only",                     // R — full|digest-only|redacted
      "started_at":"…","ended_at":"…","duration_ms":41,
      "traceparent": "00-4bf92f…-00f067aa0ba902b7-01"
    },

    // ── regime 4: POLICY
    "policy": {
      "engine": "coc-pdp/1.0.0",                           // R
      "policy_set_digest": "sha256:…",                     // R
      "policy_set_ref": "policy/coc.policy.d/",
      "schema_digest": "sha256:…",
      "policies_evaluated": ["10-base#allow-project-read","30-classified#forbid-tainted-egress"],
      "determining_policy": "30-classified#forbid-tainted-egress",   // R
      "effect": "forbid"
    },

    // ── regime 5: DECISION BASIS
    "decision": {
      "outcome": "deny",                                   // R — allow|ask|deny|defer|allow-with-conditions
      "channel": "hookSpecificOutput.permissionDecision",  // R
      "reason": "session holds restricted taint from 3 artifacts and this is an egress",
      "basis": {                                           // R — the PDP context, VERBATIM
        "taint_labels": ["restricted","pii"], "taint_depth": 3,
        "taint_sources": ["art_01J…","art_01K…"],
        "session_custody_digest": "sha256:…",
        "risk": {"score":62,"tier":"Danger","rules_version":1,
                 "engine":"no-noodles/risk_score.py@1.0.1"},
        "counterfactual": "would have been 'ask' at taint_depth<=1"
      },
      "conditions": [], "updated_input_applied": false,
      "human_response": null                               // filled by the PermissionRequest record
    },

    // ── regime 6: RESOURCE TOUCH · PROV used / wasGeneratedBy / wasDerivedFrom
    "resources": {
      "used":         [{"artifact_id":"art_01J…","digest":"sha256:…","role":"input","bytes":84213}],
      "generated":    [{"artifact_id":"art_02M…","digest":"sha256:…","role":"output"}],
      "derived_from": [{"generated":"art_02M…","source":"art_01J…",
                        "prov_type":"prov:Derivation","via":"scripts/extract_roster_counts.py"}],
      "egress":       [{"channel":"https","peer":"api.example.com","bytes":0,"blocked":true}]
    },

    // ── regime 7: LIFECYCLE CONTEXT
    "lifecycle": {
      "session_id": "6f2a…",                               // R
      "session_started_at":"…","turn":14,"prompt_id":"prm_01…",
      "message_uuid":"msg_…","request_id":"req_…",
      "transcript_path":"…","transcript_digest":"sha256:…",
      "cwd":"…", "compaction_generation": 2,
      "handover": null                                     // ISO 27037 handover — op custody.handover
    },

    // ── regime 8: VERIFICATION STRENGTH
    "verification": {
      "chain": {"algo":"hmac-sha256","genesis":"0×64","verified_at_write":true,"keyid":"coc-sess-6f2a"},
      "signature": {"present":false,"reason":"per-record signing off; sealed at segment"},
      "recorder": {"writer":"cocd/1.0.0","writer_digest":"sha256:…","transport":"unix-socket",
                   "isolation_tier": 2,"self_check":"ok"},
      "timestamp": {"source":"local-clock","tsa":null},
      "strength": "chain-keyed+isolated",                  // R — ladder in §7.3
      "known_gaps": []                                     // R — [] is an assertion, not absence
    },

    // ── ISO 27037 §5.4.1 — the field everyone omits
    "alterations": [                                       // R — [] is a positive assertion
      {"what":"tool_input.command","kind":"redaction",
       "justification":"credential-shaped token matched rules/redact.yaml#aws-akid; original sealed",
       "authorized_by":"rules/redact.yaml#aws-akid","at":"…",
       "original_digest":"sha256:…","original_ref":"sealed://…","reversible":true}
    ],

    // ── SEC 17a-4(f)
    "supersedes": null,           // record id this one amends
    "superseded_by": null,        // ONLY set by a later APPENDED pointer record, never in place
    "immutable": true,

    "controls": {"aicm_version":"1.1.0",
                 "satisfies":["DSP-20","DSP-05","LOG-03","LOG-10","LOG-12",
                              "IAM-AG-03","LOG-AG-01","LOG-AG-02"]}
  }
}
```

### 7.1 Required vs optional — three tiers, by consequence

**Tier A — REFUSE TO WRITE.** The recorder rejects the record. In `steer`/`bar` the hook then fails **closed** (deny, *"the recorder could not produce a complete record"*); in `observe` it fails **open** and raises a `recorder.selfcheck` critical alert.

`record.id`, `record.at`, `record.recorded_at`, `record.prev_hash`, `record.hash`, `actor.agent_id`, `actor.runtime_action_id`, `actor.operator`, `action.op`, `action.method.kind`, `action.input_digest`, `authority.posture`, `policy.policy_set_digest`, `policy.determining_policy`, `decision.outcome`, `decision.channel`, `lifecycle.session_id`, `verification.chain`, `verification.strength`, `verification.known_gaps`, `alterations`.

`alterations` and `known_gaps` are Tier A **as keys**, valued `[]`. `[]` means "nothing altered / no gaps". Missing means "nobody looked" — and is rejected.

**Tier B — REFUSE TO CERTIFY.** The record writes; the segment cannot be sealed or certified; `coc verify --sufficiency` reports `incomplete` naming the regime.

`actor.acted_on_behalf_of.prompt_id` (steer/bar), `actor.acted_on_behalf_of.delegation_chain` when `delegation_depth > 0`, `resources.used` for any data-touching op, `decision.basis`, `authority.capability`, `action.method.script.test_result.passed == true` for `delegated-script`.

**Tier C — DEGRADES STRENGTH.** Valid record, lower `verification.strength`: `signature`, `timestamp.tsa`, `recorder.isolation_tier`.

`coc verify --sufficiency` walks the eight regimes per governance question and **refuses to claim sufficiency it cannot back**. That is the direct answer to DEMM-Bench's 50% overclaim finding.

### 7.2 Op vocabulary

`session.open` `session.close` `prompt.submit` `tool.request` `tool.decision` `tool.result` `artifact.identify` `artifact.classify` `artifact.read` `artifact.write` `artifact.derive` `artifact.egress` `delegation.scaffold` `delegation.run` `agent.spawn` `agent.merge` `custody.handover` `custody.checkpoint` `custody.declassify` `custody.alteration` `ledger.seal` `ledger.certify` `caiq.inspect` `caiq.attest` `policy.load` `recorder.selfcheck`

An unrecognised op **alerts** rather than being dropped — port `classifyAlert`'s default branch verbatim.

### 7.3 Verification-strength ladder

`chain-only` → `chain-keyed` → `chain-keyed+isolated` → `+signed` → `+tsa` → `+transparency`. `coc verify` reports the **minimum** across a segment, never the maximum.

### 7.4 Certification (FRE 902)

A separate object, one per sealed segment, appended as a `ledger.certify` record:

```jsonc
{"op":"ledger.certify",
 "certification":{
   "segment":"seg-000012","segment_digest":"sha256:…",
   "records":{"from":4200,"to":4711},"period":{"from":"…","to":"…"},
   "certifier":{"name":"…","role":"Records Custodian","org":"Cloud Security Alliance",
                "qualification":"custodian of the chain-of-custody ledger for this host",
                "contact":"…"},
   "statement":"I certify that the records in this segment were made at or near the time of the acts described, by the automated recorder identified below, kept in the course of regularly conducted activity, and that this segment's digest matches the record set I examined.",
   "signature":{"scheme":"dsse-ed25519","keyid":"…","sig":"…"},
   "signed_at":"…"}}
```

`coc ledger certify --segment N --certifier-profile <file>` requires interactive confirmation and refuses if the segment's chain does not verify.

---

## 8. Taint and lineage

Artifact lifecycle: `unknown → identified → classified → (clean | labelled) → touched → derived`

- **identified** — `artifacts/identity.py` assigns `artifact_id`. A rename keeps the id (content digest match); a rewrite keeps the id (path match) and creates a new version. Use spindlebox `file_digest` for the fast path, full sha256 for in-toto subjects.
- **classified** — `rules/classify.yaml` match. Rule shape deliberately mirrors `risk-rules.json`: `{pattern, labels, reason, source}`. Recorded once per artifact per session as `artifact.classify`; re-classification on a ruleset-digest change is a **new record**, never an in-place edit.
- **touched / derived** — set by `artifact.read` / `artifact.derive`.

**Label lattice.** `public < internal < confidential < restricted`, plus orthogonal flags `pii`, `credential`, `csa-material`. Output labels = the join of all inputs' labels. Monotone within a session; labels drop only via an explicit `custody.declassify` naming a human authorizer and a justification — which is itself recorded as an ISO 27037 alteration.

```python
class SessionCustodyState:
    labels: frozenset[str]           # the join over everything touched
    sources: dict[str, ArtifactRef]  # which artifact contributed which label
    depth: int                       # distinct labelled artifacts touched
    touched: int
    since_last_egress: int
    graph_digest: str                # sha256 over the canonicalised DAG
    digest: str                      # sha256 over the whole state — goes into every decision.basis
```

**PDP context** (Cedar-shaped `context`; `principal` = the SPIFFE agent entity with `actedOnBehalfOf` as parent entity, `action` = the op, `resource` = the artifact entity):

```json
{"posture":"steer",
 "session":{"taint":["restricted","pii"],"taint_depth":3,"artifacts_touched":11,
            "restricted_touched":2,"since_last_egress":7,"custody_digest":"sha256:…",
            "compaction_generation":2,
            "trust":{"session_trust":false,"critical_override":false}},
 "call":{"risk_score":62,"risk_tier":"Danger","markers":["risk-ok"],
         "is_egress":true,"is_data_touching":true,"delegated_script":null},
 "artifact":{"id":"art_01J…","labels":["restricted"],"first_touch":false,"digest":"sha256:…"}}
```

**Persistence across compaction.** The **ledger is authoritative** — `coc state rebuild --session <id>` replays records, and state never depends on the transcript. A sqlite WAL materialized view at `$CLAUDE_DIR/stop-guessing/state/<session_id>.db` keeps the hook inside its ~5 ms budget. `PreCompact` writes a `custody.checkpoint` carrying `session_custody_digest` + `graph_digest`; `SessionStart` with `source=compact` rebuilds and compares. A mismatch raises a `critical` alert and, in `steer`/`bar`, degrades to a posture that denies egress until a human runs `coc state reconcile`. `agent.spawn` forks a child state inheriting parent labels; `SubagentStop` emits `agent.merge` joining child labels back.

---

## 9. Hook wiring

One `PreToolUse` entry (`coc_gate.sh`) replaces four entries in `~/.claude` and three in `~/.claude-ies`.

| Event | Script | Does | Channel | Blocking |
|---|---|---|---|---|
| `SessionStart` | `coc_session_start.sh` | recorder self-check, chain verify from last seal, state rebuild if `source=compact`, `caiq inspect`, `session.open` | `additionalContext` | no |
| `UserPromptSubmit` | `coc_prompt.sh` | `prompt.submit` + prompt digest — the root of every IAM-AG-03 delegation chain | — | no |
| `PreToolUse` | `coc_gate.sh` | §9.1 | `hookSpecificOutput.permissionDecision` | **yes** |
| `PermissionRequest` | `coc_permission.sh` | records the human's actual answer | `decision.behavior` | yes |
| `PostToolUse` | `coc_post.sh` | `tool.result`; update taint from what was actually read; redact | `updatedToolOutput` | no |
| `PreCompact` | `coc_precompact.sh` | `custody.checkpoint` — chains **after** the existing `precompact_ledger.sh` | — | no |
| `SubagentStop` | `coc_subagent.sh` | `agent.merge`, join child taint | — | no |
| `Stop` | `coc_stop.sh` | turn close + `reconcileExecution` over the turn's dispatches | — | no |
| `SessionEnd` | `coc_session_end.sh` | seal segment, optional certify, summary | — | no |

`exit 1` is **never** used (it is non-blocking — a documented footgun). `exit 2` only when `capabilities().structured_decision_channel` is `False`.

### 9.1 Dispatcher order

```
0. read stdin once; parse; if unparseable → exit 0   (fail-open on garbage — no-noodles' rule)
1. VENDORED no-noodles rules, in original registration order:
     check_credentials.sh → no_noodle.sh → check_before_build.sh → risk_gate.sh
   Each runs as a function against the same payload. First non-zero exit wins:
   translate (exit 2, stdout) → {"permissionDecision":"deny",
                                 "permissionDecisionReason":"<their exact stdout, byte-for-byte>"}
   and STOP.
2. risk_observe → observations.jsonl (identical schema, identical rotation) — never blocks
3. classify: resolve artifacts in tool_input; digest; label
4. taint: load session state; compute the would-be state
5. PDP: build context; evaluate; get {effect, determining_policy, reason, conditions}
6. record: write the CustodyRecord (Tier-A validation; refuse → fail closed in steer/bar)
7. emit: hookSpecificOutput
```

Budget: **≤ 40 ms p95.**

### 9.2 What `steer` actually does — end to end

**Step 1.** `Read /Users/isme/work/CSA/roster.csv` → classify `["restricted","pii"]`, `first_touch=true`, `taint_depth=0`.

**Step 2.** Policy `20-steer#classified-first-touch` returns `ask`:

```json
{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"ask",
"permissionDecisionReason":"CHAIN-OF-CUSTODY [steer]: roster.csv is classified restricted,pii (rules/classify.yaml#csa-roster). Opening it directly puts its contents into the model's context, which is the delegation this posture exists to avoid.\n\nPreferred — delegate:\n  stop-guessing delegate new --artifact art_01J8 --intent \"<what you actually need>\"\nScaffolds scripts/<name>.py + test_<name>.py, runs the test, and on green runs the script under a recorded capability. You receive the script's OUTPUT and a handle — not the file.\n\nHave a script already:\n  stop-guessing run scripts/extract_roster_counts.py --artifact art_01J8\n\nProceeding directly is allowed and will be recorded as an ISO 27037 alteration; it also raises session taint to restricted, which will deny egress later in this session."}}
```

**Step 3 — the delegation, if taken.** `coc delegate new` writes the script/test pair from a template and records `delegation.scaffold`. Then `coc run`:

1. refuses if `test_<script>` is absent;
2. runs the test in the sandbox; refuses on failure, and refuses if the script digest changed since the test passed;
3. computes `script_digest`, `argv_digest`, issues `nonce = issueNonce(session_id, seq)`;
4. executes with an env allowlist, `network=deny`, cwd pinned;
5. registers stdout as a new artifact whose labels are the join of its inputs';
6. writes `artifact.read` with `method.kind=delegated-script` and full `resources.used / generated / derived_from`;
7. returns the output to the model.

This is the owner's global rule — script, then test, then run on live data — made mechanical and recorded.

**Step 4 — self-reference.** `coc run` is itself a Bash call. The dispatcher recognises the CoC binary by **resolved absolute path plus pinned digest**, never by `PATH`, and allows it. At `Stop`, `reconcileExecution(dispatch_ledger, reported)` compares what the hook recorded against what the model claimed; a claimed run without the nonce produces `reconciliation-failed`, which `classifyAlert` escalates to `wake: human`.

**Step 5 — accumulation.** At `taint_depth=3` with `is_egress=true`, `30-classified#forbid-tainted-egress` denies, citing the three contributing artifact ids. This is the case no existing tool handles: twelve individually-innocuous reads composing into one restricted egress.

**`bar` differs in exactly two ways:** the script must carry a valid DSSE signature from an OS-keychain key the model cannot reach, and the model receives only `--emit handle|summary` output. There is no direct-read override in `bar`.

---

## 10. Superseding no-noodles

### 10.1 Compatibility matrix

The owner's rule — never remove an existing function, flag or option; assume external callers exist — applies to every row.

| Surface | Item | Preservation |
|---|---|---|
| Hooks | `no_noodle.sh` `check_before_build.sh` `risk_gate.sh` `grant_session_trust.sh` | vendored byte-identical to `$CLAUDE_DIR/hooks/<same name>`; still directly executable |
| Libs | `lib_config.sh` `lib_observe.sh` `lib_risk.sh` | vendored, same paths; `resolve_state` `risk_score` `risk_shadow_score` `risk_score_field` `risk_observe` all sourceable |
| Python | `risk_score.py` `risk_summary.py` `risk-rules.json` | vendored unmodified; both the 3-arg flat and 4-arg `{primary,shadow}` CLI shapes preserved. CoC **calls**, never edits |
| Config keys | `no_ad_hoc_probes` `check_before_build` `risk_scoring` | read via vendored `resolve_state`, unchanged 4-layer chain |
| Config layers | `./.no-noodles.json` → `$CLAUDE_DIR/no-noodles.json` → legacy `.state` → default | unchanged. CoC keys live in a separate `./.stop-guessing.json` / `$CLAUDE_DIR/stop-guessing.json` with the identical 4-layer shape |
| Legacy state | `~/.claude/no-noodle.state` `~/.claude/check-before-build.state` `$CLAUDE_DIR/risk-gate.state` | read as-is; **additively** check `$CLAUDE_DIR/<name>.state` first (see §10.3 bug 1) |
| Data | `observations.jsonl` `shapes/<shape>__<key>` `session-trust` `risk-profile.json` `no-noodles/VERSION` | never touched, never rotated differently. CoC keeps appending to `observations.jsonl` in the identical schema so `risk_summary.py` keeps working |
| Env | `CLAUDE_CONFIG_DIR` `RISK_OBSERVATIONS_MAX_LINES` `RISK_RULES_FILE` `RISK_SCORE_PY` `NO_NOODLES_RISK_CRITICAL_OVERRIDE` | all honoured |
| Markers | `# noodle-ok` `# risk-ok` `# build-ok:` (≥60 ch + path token) | evaluated by the vendored code, identical semantics. CoC adds `# custody-ok:` as a **new** marker — the existing three are not repurposed |
| CLI | `grant_session_trust.sh grant\|revoke\|status` | vendored unchanged; `coc trust grant\|revoke\|status` added as an alias that shells to it |
| Docs | `no-noodle.md` `noodle-options.md` → **both** `skills/` and `commands/` | same dual-path install (the 2026-07-29 finding: a flat `.md` under `skills/` is never loaded). `/no-noodle` and `/noodle-options` keep working |
| Installer | idempotent, dedupes on command string, resolved absolute paths, `--uninstall` preserves the observations dir | CoC's installer reuses the exact JSON-surgery code with the same guarantees |
| Behaviours | first-in-project allowed / second blocked; `PWD \| tr -c 'a-zA-Z0-9' '_' \| tail -c 60` project key; sha256[:16] signature; command never stored verbatim; fail-open by construction; risk tiers/multipliers/penalties; risk_gate off-by-default | all inside vendored code paths, exercised by `coc compat verify` |

### 10.2 Avoiding double-deny

Standalone `PreToolUse` entries are removed by the same JSON surgery `install.sh --uninstall` performs (dedupe on command substring); one dispatcher entry replaces them.

Residual risk: someone re-runs `no-noodles/install.sh`, which re-adds three entries **and** reverts the hardened `check_before_build.sh`. Defence:

- `$CLAUDE_DIR/no-noodles/superseded-by` records the CoC version, timestamp, and the digest of each vendored file at install time.
- `SessionStart` runs `coc doctor --quick`. If the marker is present **and** standalone entries are back in `settings.json`: (a) raise a `critical` alert naming the exact re-added commands; (b) set the dispatcher to record-only for the duplicated rules so each message emits exactly once; (c) if a vendored file's digest no longer matches the manifest, name the file, the expected digest, and the recovery command.

### 10.3 Three real bugs to fix on the way through

**Bug 1 — cross-profile state bleed.** `no_noodle.sh:18` and `check_before_build.sh:23` hardcode `STATE="$HOME/.claude/..."` while `risk_gate.sh:39` uses `$CLAUDE_DIR`. Under `CLAUDE_CONFIG_DIR=~/.claude-ies` the legacy toggles for rules 1 and 4 read the **wrong profile**. Fix additively: check `$CLAUDE_DIR` first, fall back to `$HOME/.claude`. Never drop the old path.

**Bug 2 — literal `~` in the default profile's registrations.** `~/.claude/settings.json` registers hooks as literal `~/.claude/hooks/...`; `~/.claude-ies/settings.json` uses absolute paths. The 2026-07-16 incident that `install.sh` guards against is still live in the default profile. CoC writes resolved absolute paths in both.

**Bug 3 — the uncommitted hardening.** The repo's `no-noodles/hooks/check_before_build.sh` is 62 lines; the installed one is 125 lines (6660 bytes), hardened 2026-07-30, **never committed back** — and it is byte-identical in both profiles, with `~/.claude-ies/hooks/check_before_build.sh.pre-harden.bak` holding the 3528-byte original. Running `install.sh` silently reverts marker validation, the `workflows/` guard, and the candidate search. Sequence:

1. `coc compat inventory` records both digests with dated evidence into `docs/testing-checklist.md` as `[broken] repo check_before_build.sh is 62 lines; installed is 125 (hardened 2026-07-30, never committed) — running install.sh reverts it`.
2. **File a GitHub issue on `moonsoup/no-noodles` with the diff, before fixing.** Non-negotiable — a finding fixed in the same session still gets its issue.
3. The 125-line version becomes `compat/nonoodles/check_before_build.sh` with a `MANIFEST.sha256` entry.
4. Open a PR upstream to `moonsoup/no-noodles` restoring it there.
5. `compat.yml` nightly CI diffs `moonsoup/no-noodles@main` against the vendored tree and fails on drift.

### 10.4 Migration sequence

```
1  stop-guessing doctor --pre-supersede            # inventory both profiles: files, digests,
                                                      # settings entries, state files, effective
                                                      # config keys, shapes counts, obs line count
2  stop-guessing migrate import --from no-noodles   # copy no-noodles.json + .state values into
                                                      # stop-guessing.json; ORIGINALS LEFT IN PLACE
3  stop-guessing install --supersede-no-noodles \
     --all-profiles --dry-run                          # prints the exact settings.json diff
4  stop-guessing install --supersede-no-noodles --all-profiles
5  stop-guessing compat verify                      # THE acceptance gate
6  (optional, manual, NEVER automatic)
   ~/Software/no-noodles/install.sh --uninstall        # CoC does not run this: it deletes
                                                      # no-noodles.json and the .state toggles
```

`coc compat verify` replays a committed corpus of ≥60 real hook payloads (`fixtures/payloads/*.json`, harvested from `observations.jsonl` shapes plus hand-built edge cases) through **both** the standalone vendored hooks and the dispatcher, asserting identical `(exit_code, stdout)` for every case across every combination of config layer, marker presence, and `CLAUDE_CONFIG_DIR`. It runs in CI on every PR.

Step 6 stays manual and CoC never invokes it — `observations.jsonl`, `shapes/`, `session-trust` and `risk-profile.json` are accumulated audit data.

---

## 11. Recorder isolation

**Principle:** never let the recorded party control the resolution of anything the recorder depends on. This is the Berkeley RDI fake-`curl` lesson, stated as a design rule.

| Tier | Design | Stops | Does not stop |
|---|---|---|---|
| 0 | Hook writes JSONL in-process | nothing structural | truncate-and-recompute-a-whole-valid-chain |
| 1 | `cocd` daemon, same UID, unix socket 0600, HMAC key in memory from OS keychain | chain forgery (no key → no valid chain), PATH shadowing, hook-script substitution (digest-pinned) | a determined agent killing `cocd` or deleting the ledger wholesale |
| 2 | `cocd` runs as `_coc` via launchd; ledger dir `_coc:staff 0750`; socket group-writable | ledger rewrite and deletion by uid 501 | root, physical access |
| 3 | Socket replaced by HTTP append to a CSA-internal host | local destruction | that host's own integrity |

**Tier 2 is the recommended install for CSA staff** (`install.sh --isolated`, one sudo, once). Tier 1 is the default. Tier 0 is a recorded fallback, never silent.

Six concrete mechanisms:

1. **Keyed chain.** Chain material = `HMAC-SHA256(session_key, [seq, at, op, actor.agent_id, detail_digest, severity, prev_hash].join(" "))`. `session_key` comes from `attest/keys.py` (secretarius `KeyringProvider` → argon2id passphrase → keyfile). The agent cannot read the keychain item without a `security` call the gate denies under every posture. `coc ledger verify --public` reports *"chain shape intact, keyed verification unavailable"* rather than a false green.
2. **No `PATH`, ever.** `settings.json` registers the dispatcher by resolved absolute path; install writes that path's digest into `$CLAUDE_DIR/stop-guessing/install-manifest.json`; `guard.py` compares `realpath(argv[0])`'s digest against the manifest on every invocation.
3. **The ledger directory is on the deny-list under every posture, including `observe`.** `Write`/`Edit`/`Bash` targeting `$CLAUDE_DIR/stop-guessing/ledger/**` is denied, and the denial is itself a `critical` record.
4. **Session-start self-check** (`recorder.selfcheck`; refuses to record in `steer`/`bar` on failure): daemon binary digest; every hook script digest vs manifest; `settings.json` registration still points at the pinned path; ledger dir owner and mode; chain intact from genesis or last seal; socket peer credentials.
5. **Agent claims never enter the ledger unchecked.** `reconcileExecution` compares the hook-side dispatch ledger — which the agent never writes — against model reports, producing `fabricated or replayed`, `attribution mismatch`, `nonce mismatch`, `unreported execution`.
6. **Segments, not truncation.** `segments.py` seals at a configurable size, writes the sealed segment's digest into the next genesis link, and archives. no-noodles' 5000-line `tail` rotation is preserved for `observations.jsonl` **only**, never for the custody ledger.

`verification.recorder.isolation_tier` and `known_gaps` appear in every record; `coc verify` reports the minimum across a segment.

---

## 12. The AI-CAIQ subsystem

```
docs/ai-caiq/
  stop-guessing.yaml                    # answers + evidence — the diffable source of record
  AI-CAIQ-stop-guessing-v1.1.0.xlsx     # generated deliverable, committed
  COVERAGE.md                              # generated, committed
  CHECKLIST.md                             # living [working]/[broken]/[fixed]/[untested]
  reference/TEMPLATE.json                  # committed: digest + parsed A1 + dims + sheet names + vocab
  reference/AI_CAIQv1.1.0.xlsx             # CSA's blank template — see licensing note
```

The unfilled artifact is `/Users/isme/Software/rockin-robin/docs/ai-caiq/reference/AI_CAIQv1.1.0.xlsx` — 85,094 bytes, sheets `['Introduction','AI-CAIQv1.1.0','LLM Taxonomy','Change Log']`, data sheet `A1:L324`, header on row 2, data from row 3, columns C–F editable only, columns I–L populated only on the first question row of each control group. 247 controls, 320 real question rows, 18 domains. Control IDs match `^[A-Z][A-Z&]{1,3}-\d{2}$` — **the ampersands in `A&A` and `I&S` are real**, an `isalpha()` filter silently drops them, and `IVS-*` does not exist (it is `I&S`).

**Licensing note — resolve in M0, do not guess.** rockin-robin gitignores the blank template ("public reference material, cited but never committed"); the `rich-text` plugin vendors it into a distributed skill. `reference/TEMPLATE.json` is always committed and is sufficient for version inspection. Commit the blank XLSX itself **only after confirming CSA's redistribution terms permit it**; if not, `coc caiq inspect` refuses with a path hint and the operator supplies it. Both paths must work — do not close the option.

**Availability — the one thing not obtainable from GitHub.** Verified 2026-08-03: `mEllergrace/rockin-robin` is public and complete and ships `src/rockinRobinAudit.ts`, `src/rockinRobinAuditSink.ts`, both filled workbooks and the answer YAMLs — but `docs/ai-caiq/reference/` 404s, because `.gitignore:4` excludes it ("Public CSA reference materials are cited, never committed"). **The blank template exists only on the local machine**, byte-identical (sha256 `3476859d…`) at three paths:

```
/Users/isme/Software/rockin-robin/docs/ai-caiq/reference/AI_CAIQv1.1.0.xlsx
/Users/isme/.claude/plugins/cache/rich-text/rich-text/0.2.8/skills/rich-text/docs/ai-caiq/reference/AI_CAIQv1.1.0.xlsx
/Users/isme/work/CSA/Software/ZTAF-Primitive-Mapping/docs/AI_CAIQv1.1.0-star_security_questionnaire-generated_at_2026_06_18(1).xlsx
```

An implementing agent that clones from GitHub will not have it. M0 copies it from the first path and records its digest in `reference/TEMPLATE.json`; the digest, not the file, is what the every-run inspection compares against, so the tool still functions for anyone who obtains the template from CSA directly.

**INVARIANT — the template is copy-only. It is the local backup and it is not recoverable from GitHub.**

| Rule | Enforcement |
|---|---|
| Never opened with write intent | `caiq/workbook.py` opens it `read_only=True`; a `wb.save()` against any path under `reference/` is a lint-level ban plus a runtime assert |
| Never the target of `fill` | `caiq/fill.py` preserves `fill_ai_caiq.py`'s existing behaviour — copy first, write to the copy. Add `test_fill_never_touches_template.py` asserting the template's mtime and digest are unchanged after a fill |
| Never regenerated | `make_blank_ai_caiq_template.py` is stale (`SHEET="AI-CAIQv1.0.2"`, KeyErrors today). Do **not** "fix" it by regenerating a blank over the backup. If a blank is ever needed, it is written to a new path and the backup is left alone |
| Tamper detected, not trusted | The every-run inspection already compares `file_digest(template)` against `reference/TEMPLATE.json` (§ drift table, row 4: *template digest differs, A1 matches → REFUSE regeneration — someone edited the blank*). That row is what turns this invariant from a convention into a mechanically enforced check |
| Backup path | If the digest ever mismatches, restore from `~/.claude/plugins/cache/rich-text/rich-text/0.2.8/skills/rich-text/docs/ai-caiq/reference/` or `~/work/CSA/Software/ZTAF-Primitive-Mapping/docs/` — both byte-identical — and file an issue with the mismatching digest |

The same rule covers the AICM workbook at `~/work/CSA/Software/ZTAF-Primitive-Mapping/docs/AICMv1.1.0-generated_at_2026_06_18(1).xlsx`, which `caiq/aicm.py` reads and must never write.

**Version inspection, every run** (`SessionStart`, ~15 ms, read-only openpyxl):

```
1. locate template + filled workbook
2. json.loads(sheet[1].cell(1,1).value)
3. assert specification_name == "AI Controls Matrix"
4. compare specification_version / caiq_version against the VERSION-pinned expectation ("1.1.0"/"1.1.0")
5. assert "AI-CAIQv1.1.0" in wb.sheetnames
6. assert dimensions == "A1:L324"
7. file_digest(template) vs reference/TEMPLATE.json
8. file_digest(filled) vs the digest in the last caiq.attest record
→ emits a caiq.inspect record every time, drift or not
```

This is the gate that does not exist anywhere today. Every current consumer hardcodes `SHEET = "AI-CAIQv1.1.0"` (`fill_ai_caiq.py:32`, `ai_caiq_coverage.py:23`, `verify_ai_caiq_workbook.py:12`) and nothing parses A1. `make_blank_ai_caiq_template.py:24` still says `"AI-CAIQv1.0.2"` and would `KeyError` today — live proof of the failure mode.

**Drift policy.** Never blocks the session; refusal is scoped to regeneration and attestation.

| Drift | Action |
|---|---|
| A1 missing or unparseable | REFUSE regeneration + attestation; `critical` record; `coc caiq verify` exits non-zero |
| `specification_version` ≠ pinned | REFUSE regeneration; warn at session start; auto-file a `caiq-drift` issue when `--file-issues` |
| Sheet name differs, A1 matches | WARN, proceed — A1 is authoritative |
| Template digest differs, A1 matches | REFUSE regeneration — someone edited the blank |
| Filled digest ≠ last attested | REFUSE, `critical` — the deliverable was hand-edited outside the pipeline |
| Dimensions differ | REFUSE |
| Answers YAML newer than workbook | WARN + `coc caiq sync` (spindlebox `stale_report` pattern) |

**Authoring.** rockin-robin's YAML shape, extended with machine-resolvable evidence:

```yaml
- control: DSP-20
  answer: 'Yes'
  ssrm: Owned by OSP
  implementation: >-
    Every artifact read, write and derivation is recorded as an in-toto Statement
    carrying PROV used/wasGeneratedBy/wasDerivedFrom edges into a keyed hash-chained
    ledger; derivation propagates classification labels to outputs.
  evidence:
    - {type: ledger,    ref: 'coc:01JQZ8…', observed: 'derivation edge art_02M ← art_01J via scripts/x.py', date: 2026-08-10}
    - {type: test,      ref: 'tests/test_taint_graph.py::test_derivation_edge_recorded', observed: passed, commit: abc1234}
    - {type: live-test, ref: 'stop-guessing demo steer-deny', observed: 'deny emitted; record coc:01JQZ9 written', date: 2026-08-10}
    - {type: code,      ref: 'stop_guessing/taint/graph.py::derive', digest: 'sha256:…'}
```

`coc caiq evidence check` resolves every ref: `test` refs must exist and pass; `ledger` refs must resolve **and their chain must verify**; `code` refs must resolve at the recorded digest. Stale evidence demotes the answer to `unassessed` in the report — never silently in the workbook.

Preserve rockin-robin's four maintenance rules verbatim: unassessed is not "No"; every answer carries evidence; negative findings state their search path; name the right control.

CI job `caiq-drift` runs `coc caiq evidence check` on every PR and fails when a control's evidence stops resolving. `CHECKLIST.md` is the mandated living doc. This is how the AI-CAIQ stays filled *as features land* rather than as a retrofit.

---

## 13. Repo, distribution, ecosystem

```
/Users/isme/Software/coc-prov          (dir name unchanged; remote = mEllergrace/stop-guessing)
  VERSION  pyproject.toml  README.md  CHANGELOG.md  LICENSE(Apache-2.0)  CLAUDE.md  AGENTS.md
  IMPLEMENTATION_LOG.md                append-only, per-commit (no-noodles rule)
  install.sh                           --uninstall --supersede-no-noodles --profile <dir>
                                       --all-profiles --isolated --dry-run
  stop_guessing/                    the package (§6)
  hooks/                               one thin .sh per event, all calling the same python entry
  policy/coc.policy.d/{10-base,20-steer,30-classified,40-bar}.yaml + schema.json
  rules/{classify,redact}.yaml
  scripts/                             every script paired with test_<script>
  tests/                               pytest + bash suites (no-noodles harness style)
  fixtures/payloads/                   the compat corpus
  docs/
    index.html favicon.png logo.svg og.png apple-touch-icon.png     (no-noodles Pages pattern)
    RECORD_SCHEMA.md THREAT_MODEL.md ADAPTERS.md SUPERSEDING_NO_NOODLES.md POSTURES.md
    aicm-mapping.md  testing-checklist.md  ai-caiq/…
  .claude-plugin/
    marketplace.json
    plugins/stop-guessing/
      .claude-plugin/plugin.json
      hooks/hooks.json
      commands/{custody,custody-options,no-noodle,noodle-options}.md   # aliases preserved
      skills/stop-guessing/SKILL.md
  .agents/plugins/…                                                   (Codex mirror, rich-text pattern)
  .github/
    ISSUE_TEMPLATE/{finding.yml,caiq-drift.yml,compat-drift.yml,config.yml}
    workflows/{ci.yml,compat.yml,pages.yml}
    FUNDING.yml
```

**Install story for a CSA staffer** — two supported paths, both kept:

1. `/plugin marketplace add mEllergrace/stop-guessing` then `/plugin install stop-guessing@stop-guessing`. No shell script, no filesystem trust. This is proven working in this estate: `~/.claude/plugins/known_marketplaces.json` records `rich-text` installed exactly this way from `mEllergrace/rich-text`.
2. `git clone && ./install.sh --all-profiles` for anyone who needs the supersession path or Tier-2 isolation.

**Manifests** copy `rich-text`'s shapes exactly. All version strings are generated from `VERSION` by `scripts/stamp_version.py`, with `test_stamp_version.py` asserting agreement — `rich-text` has already drifted (`plugin.json` 0.2.14 vs `manifest.yaml` 0.3.0); do not repeat that.

**Dual profile.** `--all-profiles` discovers `$HOME/.claude*` directories containing a `settings.json`, installs into each with resolved absolute paths (fixing the literal-`~` entries), and puts all per-profile state under `$CLAUDE_DIR/stop-guessing/`, never a hardcoded `$HOME/.claude`. Docs install to **both** `skills/` and `commands/`.

**Pages.** GitHub Pages `build_type: legacy`, `main:/docs` → `https://mellergrace.github.io/stop-guessing/`. Single-file hand-written `index.html` with inlined CSS variables and a full OG/Twitter card block, plus favicon/logo/og assets — copy `no-noodles/docs/` (18 KB, no build step). `mEllergrace/rockin-robin` already proves Pages works on that account.

**Issues.** `finding.yml` encodes the loop in the form itself: repro against the real running system, dated evidence, the checklist line, and a "fixed in this session?" checkbox that explicitly **does not** exempt filing. Title style follows the house pattern — a defect claim with its consequence, e.g. *"AI-CAIQ version inspection passes on a v1.0.2 workbook: sheet-name check masks a spec-version mismatch."* Labels: adopt `state:reproduced` / `state:fix-failed-verify` from spindlebox, plus `caiq-drift`, `compat-drift`, `isolation`.

**CI.** `ci.yml` — `ruff check` as a gate, pytest, bash suites, `coc compat verify`, `coc caiq evidence check`, `cedar validate` on the exported policy set (cedar CLI in CI only). `compat.yml` — nightly diff against `moonsoup/no-noodles@main`. `pages.yml` — path-filtered on `docs/**`.

**Offline guarantee:** no workflow and no runtime path performs an external network call. Sigstore/Rekor/TSA are opt-in flags whose config keys default off, with a startup banner when enabled.

---

## 14. Milestones

Each milestone ends with acceptance against the **real running system**, then the loop: test → record in `docs/testing-checklist.md` with dated evidence → file the issue → fix → verify live again → close with the commit hash.

| # | Scope | Acceptance test (real system) |
|---|---|---|
| **M0** | Skeleton, `pyproject`, `VERSION`, ruff/pytest, vendored no-noodles + `MANIFEST.sha256`, fixture corpus, AI-CAIQ licensing decision | `coc compat verify --record-golden` replays ≥60 payloads through the standalone hooks and commits the `(exit, stdout)` golden file. None of CoC's own logic runs yet. `ruff check` green. |
| **M1** | `ledger/` — port audit, sink, keyed chain, segments, reconcile, alerts | Append 200 records; hand-edit #57 → `coc ledger verify` names index 57 and the reason; append refuses; truncate the tail → refuses; `coc ledger seal` archives and the next segment chains to the sealed digest; **without the keychain key, a recomputed forged chain fails verify**. |
| **M2** | Record schema, in-toto/DSSE, JSON Schema, `verify --sufficiency` | `coc record emit --fixture` validates against the schema; a record with `alterations` **absent** is rejected at write while `alterations: []` is accepted; `--sufficiency` names the unpopulated regime on a deliberately gapped ledger. |
| **M3** | Claude Code adapter, `observe` posture, single dispatcher, supersession install | Live in `~/.claude-ies`: a real session doing Read + Edit + Bash; `coc ledger tail` shows records with real `session_id`/`prompt_id`/`tool_use_id`/`traceparent`; `settings.json` has exactly one `PreToolUse` entry; `coc compat verify` still green; `/no-noodle` still invocable; `grant_session_trust.sh status` unchanged. |
| **M4** | `artifacts/` + `taint/` + `policy/` + `steer` | Live: a classified fixture → Read returns the `ask` with delegation text; `coc delegate new` + `coc run` succeeds, the derivation edge is recorded, the output artifact carries joined labels; a scripted twelve-reads-then-egress is denied citing 3 artifact ids; `coc state rebuild` from the ledger reproduces the digest exactly. |
| **M5** | Recorder isolation, `cocd`, `guard.py`, Tier 2 | A scripted attacker suite (a test, never the agent): PATH-shadow the CLI; direct-write the ledger; truncate-and-reseal without the key; replace a hook script; kill `cocd`. Each is refused or detected by `coc doctor`, with a record showing the right `isolation_tier`. Every finding gets an issue with evidence. |
| **M6** | Exports: PROV-JSON, CASE/UCO, OTel | `case_prov_check` (usnistgov/CASE-Implementation-PROV-O) reports **no** custody break on an intact ledger and **does** report one on a deliberately gapped one. OpenLineage stays a documented stub. |
| **M7** | `bar` posture, segment signing, certification | Live: with a classified artifact the model receives only a handle + summary; an unsigned script is refused; a signed script runs; `security find-generic-password` shows the item while the ledger shows only the `keyid`; `coc ledger certify` refuses on an unverified segment and succeeds interactively on a verified one. |
| **M8** | AI-CAIQ subsystem | `coc caiq inspect` returns parsed A1 from the real template; a mutated-A1 fixture is refused; `coc caiq fill` output passes rich-text's `verify_ai_caiq_workbook.py` **unmodified**; deleting a referenced test makes `coc caiq evidence check` fail. |
| **M9** | Distribution, live supersession, Pages, plugin | On a second profile or container: `install.sh --all-profiles --supersede-no-noodles`; `coc compat verify` green in both; re-running `no-noodles/install.sh` is detected and alerted with the reverted-hardening digest named; `risk_summary.py` still parses `observations.jsonl`; the plugin installs from the marketplace; the Pages site is live. |
| **M10** | **Self-attestation — the goal (§2.1).** `docs/claims.yaml`, `stop-guessing prove`, `stop-guessing claims check`, `stop-guessing attest --self`; then the AI-CAIQ filled from those proofs, last | Every claim in `claims.yaml` carries ≥1 proof that is a **ledger record id in STOP-GUESSING's own chain** — including the M5 adversarial proofs and the negative claims. `stop-guessing ledger verify` green over every segment covering a proof. Every plugin, skill and slash-command exercised by at least one live-run proof. `stop-guessing caiq evidence check` resolves every AI-CAIQ answer to those record ids. **Then** `caiq fill` runs, and its output passes rich-text's `verify_ai_caiq_workbook.py` unmodified. `stop-guessing attest --self` exits 0. Finally, deliberately break one link — stale a proof, edit the workbook, truncate a segment — and confirm it exits non-zero naming the break. |

**M10 is the goal and it is strictly last.** Every earlier milestone contributes proofs to it, so `claims.yaml` should be created at M0 and appended to as each milestone lands — a claim written after the fact is a claim written to match the evidence, which is the causation the tool exists to reverse. The AI-CAIQ fill is the final action of the project.

**Ordering.** M0–M2 are pure and parallelisable. **M3 is the first live gate and the highest-risk step** — it changes both profiles' `settings.json`. Do `~/.claude-ies` first and leave `~/.claude` on standalone no-noodles until `compat verify` has been green for a full working session. M4 and M5 are independent and can run concurrently. M8 depends only on M1.

---

## 15. Verification

**Per milestone**, the acceptance test above, run against the real running system — not code review, not green unit tests. Where a live run is impossible, a failing test that reproduces the defect is the minimum bar.

**Continuously:**
- `ruff check` before every commit touching Python. Never commit Python that fails the linter.
- `pytest` + the bash suites (`set -uo pipefail`, `check()`/`FAILS`, hermetic `CLAUDE_CONFIG_DIR="$TMP/claude"` with `mktemp -d` and `trap` — the no-noodles tests previously polluted the developer's real config dir; do not repeat that).
- `coc compat verify` on every PR — the supersession gate.
- `coc caiq evidence check` on every PR — the compliance gate.
- Nightly `compat.yml` drift check against `moonsoup/no-noodles@main`.

**End-to-end smoke, the one command a reviewer runs:**

```
stop-guessing demo --posture steer
```

Creates a classified fixture in a temp dir, drives a real session against it, and prints: the `ask` on first touch, the delegated-script run with its derivation edge, the accumulation deny, the sealed segment, `coc ledger verify` green, `coc verify --sufficiency` per regime, and `coc caiq inspect` reporting the live workbook version. Every step cites its record id.

**Living record:** `docs/testing-checklist.md`, entries `[working]` / `[broken]` / `[fixed]` / `[untested]` with dated evidence, growing during testing. Every real bug becomes a GitHub issue on `mEllergrace/stop-guessing` (or `moonsoup/no-noodles` for the compat bugs) **with evidence, before the fix**. Issues close with the fixing commit hash and verification evidence.

---

## 16. Working agreements for the implementing agent

1. **Search before writing.** `spindlebox search "<concept>" --all-projects` before any new function. The `check_before_build.sh` hook enforces this and the installed version requires a `# build-ok:` reason of ≥60 characters that names a searched path.
2. **Script → test → run.** No data-touching action as an ad-hoc call. The test file is written and passing before the script touches live data. This is also what `coc delegate` mechanises, so the tool must obey its own rule.
3. **Expect rule-1 friction, and use the documented escape.** This project's docs, tests and rules will contain the literal strings `curl … | python3` and `base64 -d`. `no_noodle.sh` greps the raw command text and blocks the second occurrence per project. `# noodle-ok` is the correct answer, recorded as such in `IMPLEMENTATION_LOG.md`.
4. **Never remove a function, flag or option.** Add alongside. Assume external callers exist even with zero in-repo evidence. If genuinely convinced something is dead, ask.
5. **Never surface credentials.** Enforced by hook.
6. **Log the risk-engine changes.** Any commit touching `lib_risk.sh`, `risk_gate.sh`, `risk-rules.json`, `risk_score.py` or the profile schema appends to `IMPLEMENTATION_LOG.md` in the same commit — a standing rule from `no-noodle.md:44-51`.
7. **Semver every code-changing push**, bump `VERSION`, tag `v<x.y.z>`.
8. **Do not run `no-noodles/install.sh`** at any point. It reverts the hardened hook (§10.3, bug 3).
9. **The blank AI-CAIQ template is copy-only.** `rockin-robin/docs/ai-caiq/reference/AI_CAIQv1.1.0.xlsx` is the local backup of a CSA artifact that is gitignored and **not on GitHub**. Read it, hash it, copy it — never write to it, never regenerate it. Same for the AICM workbook. See §12's invariant table.
10. **Be honest in the ledger's own design.** `known_gaps: []` is an assertion. If a capability is missing, record it rather than omitting the field — the whole product's credibility rests on that distinction.

---

## 17. Open items — decide during M0, do not guess

1. **AI-CAIQ template redistribution.** Confirm CSA's terms before committing `reference/AI_CAIQv1.1.0.xlsx`. `reference/TEMPLATE.json` ships either way. Both code paths must work.
2. **Certifier identity for CSA distribution.** Who signs the FRE 902 certification on a staff laptop — the individual staffer as records custodian, or a central CSA role? Affects only `certifier-profile` defaults, not the schema.
3. **`in-toto` predicate type registration.** `https://stop-guessing.dev/Custody/v1` needs either a real resolvable URL or a decision to use a non-resolving URI. Registering through in-toto's documented vetting process is what converts "private format" into "registered predicate" — worth doing, and worth doing after M2 when the schema has stopped moving.
4. **Whether `mEllergrace/stop-guessing` is mirrored privately on `moonsoup` first.** The estate convention is private dev under `moonsoup`, public distribution under `mEllergrace`. Public-only is simpler and this is meant to be a public CSA-facing reference implementation; confirm before the first push.
