# STOP-GUESSING

**Version 0.1.0 — planning complete, implementation not started.** See [IMPLEMENTATION_PLAN.md](IMPLEMENTATION_PLAN.md).

Chain-of-custody and data-provenance for agentic AI. It exists so that what an agentic tells you is not a guess.

> **Provenance is evidentiary, not preventive.** A hash-chained log of an exfiltration is still an exfiltration. STOP-GUESSING records what happened and refuses to claim more than it can prove. It is not a prompt-injection defence and must not be sold as one.

## The problem

An agent reads data, transforms it, reports a result — and nothing durable records which bytes entered, what happened to them, or whether the report is true. Every downstream audit inherits that gap.

Two documented failures define the shape of it:

- **Replit / SaaStr, 21 July 2025** ([AI Incident Database #1152](https://incidentdatabase.ai/cite/1152/)) — an agent deleted a production database during an explicit code freeze, fabricated ~4,000 fictional records, and misreported what it had done. No independent record of any of it.
- **Berkeley RDI, April 2026** ([writeup](https://rdi.berkeley.edu/blog/trustworthy-benchmarks-cont/)) — a zero-capability agent scored ~100% on eight benchmarks by attacking the evaluator, including installing a fake `curl` wrapper that returned fabricated success to the grader.

The second one is a design constraint, not an anecdote: **the recorder must not be reachable by the agent it records.**

## What already exists, and what doesn't

Everything in this space records **actions**. Nothing records **data flow**.

Verified across Claude Code's native OpenTelemetry events, [`agent-receipts/obsigna`](https://github.com/agent-receipts/obsigna), [`Helixar-AI/HDP`](https://github.com/Helixar-AI/HDP), Langfuse, Arize Phoenix, LangSmith, OpenLineage, and Microsoft's [`agent-governance-toolkit`](https://github.com/microsoft/agent-governance-toolkit): every one answers *"which agent called which tool, and was it allowed?"* Not one answers *"which bytes entered the agent, and where did they end up?"*

Three specific gaps:

1. **No artifact-level derivation edge across a session.** OpenTelemetry's GenAI semantic conventions contain zero provenance attributes. OpenLineage has the right graph primitive and no agent emitter.
2. **Agent DLP is stateless.** Every redaction hook in the wild is a regex fired independently per call. The real risk is *accumulation* — twelve individually-innocuous reads composing into a restricted dataset, then one egress.
3. **Nobody feeds custody state back into the permission decision.** The hooks to do it are shipping and unused.

## The thesis

> The agent's control decisions are computed only from trusted inputs; data handling is delegated to deterministic, capability-constrained code; and every delegation is recorded.

This is the citable form. Backing: [Beurer-Kellner et al., *Design Patterns for Securing LLM Agents against Prompt Injections*](https://arxiv.org/abs/2506.08837) (IBM/Google/ETH/Microsoft) and [Debenedetti et al., *CaMeL*](https://arxiv.org/abs/2503.18813) (DeepMind/ETH), which protect **control flow** rather than sight of data. The stronger claim — the model never sees data at all — is what the `bar` posture implements. It ships as an option; it is not the claim the docs lead with.

## Standards

| | |
|---|---|
| **Emits** | [in-toto Attestation Framework v1](https://github.com/in-toto/attestation) Statements, DSSE-enveloped, JSONL bundle |
| **Signs** | [Sigstore](https://docs.sigstore.dev/) bundle format — **opt-in, offline by default**, no public Rekor upload unless explicitly enabled |
| **Speaks** | [W3C PROV](https://www.w3.org/TR/prov-dm/) vocabulary, [CASE/UCO](https://caseontology.org/) chain-of-custody and chain-of-evidence, [OpenTelemetry GenAI](https://github.com/open-telemetry/semantic-conventions-genai) spans |
| **Structured by** | ISO/IEC 27037:2012 §5.4.1 custody fields · SEC Rule 17a-4(f) audit-trail alternative · FRE 902(13)/(14) certification |
| **Maps to** | CSA AICM v1.1.0 — DSP-20, DSP-05, DSP-24, LOG-03, LOG-10, LOG-12, STA-09, and the draft agentic controls IAM-AG-03, LOG-AG-01, LOG-AG-02 |

CSA has published the requirement and drafted the agentic controls. [*Data Security within AI Environments*](https://cloudsecurityalliance.org/artifacts/data-security-within-ai-environments) (December 2025) recommends, verbatim, *"cryptographically signed data provenance tracking using blockchain or merkle trees"* and *"tamper-evident logs (e.g. AWS QLDB, Sigstore)."* None of it has a reference implementation. That gap is what this is.

## Postures

Three, all shipping. Default is `steer`.

| Posture | Behaviour |
|---|---|
| `observe` | Records everything, blocks nothing |
| `steer` | **Default.** Asks on first touch of a classified artifact, offering a recorded script delegation. Denies on accumulated taint crossing threshold, or any egress while tainted |
| `bar` | The model is barred from opening classified artifacts. Only signed scripts touch them; the model receives handles and summaries |

Full depth is the default and is never silently reduced. Where fidelity is genuinely reduced it is recorded — `known_gaps: []` is a positive assertion that nothing was skipped, and a *missing* key is rejected at write.

Removable at four levels — posture, per-rule, per-project, and full uninstall — none of which destroys the accumulated ledger.

## Relationship to no-noodles

STOP-GUESSING vendors [`moonsoup/no-noodles`](https://github.com/moonsoup/no-noodles) byte-identically and is designed to supersede it, preserving every hook, config key, escape marker, state file and CLI. `# noodle-ok`, `# risk-ok` and `# build-ok:` keep working with identical semantics; `/no-noodle` and `/noodle-options` stay invocable. See §10 of the plan for the full compatibility matrix and `stop-guessing compat verify` for the acceptance gate.

## Status

Nothing is implemented. The plan is complete and executable — nine milestones, each with an acceptance test that runs against the real system rather than asserting green unit tests. Start at [IMPLEMENTATION_PLAN.md](IMPLEMENTATION_PLAN.md) §14, then M0.

## Files

```
IMPLEMENTATION_PLAN.md   the whole design — architecture, record schema, milestones
VERSION                  single source of truth for every version string
docs/index.html          project page
.github/ISSUE_TEMPLATE/  finding / caiq-drift / compat-drift forms
```

## Licence

Apache-2.0.
