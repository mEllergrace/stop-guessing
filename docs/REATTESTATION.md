# Re-attestation runbook

**Status: approved procedure. Run it in full every time the toolchain changes.**

`stop-guessing attest --self` exiting 0 is not a permanent state. It is a statement about a
specific set of code, procedures and ledger records at a specific moment. Change any of them and
the statement has to be re-earned.

This runbook is the "several times later" case: a bug is found, a fix lands, and the attestation
must be rebuilt. It is deliberately the *same* sequence as the first time, in the same order, with
no shortcut for "small" changes — a shortcut is how the direction of causation gets reversed.

---

## The invariant

> Evidence is produced first, in a ledger the recorded party cannot forge. The AI-CAIQ is
> **rendered** from it, last. Nothing is ever written in the other direction.

Three things follow, and they are enforced rather than trusted:

| You might be tempted to | What happens |
|---|---|
| Hand-edit `proofs:` in `docs/claims.yaml` | `claims check` reports the ref as *not found* or *recorded against another claim* |
| Hand-edit the filled workbook | Its digest no longer matches the one pinned in CLAIM-21's proof record |
| Fix a procedure and keep its old proof | Every proof from that procedure is reported *produced by a since-modified procedure* |

All three are demonstrated in `tests/test_prove.py` and were re-run live before this runbook was
written. Do not rely on discipline where the tool already refuses.

---

## When to run it

| Change | Required |
|---|---|
| Any change to `stop_guessing/` | **Full re-run** |
| Any change to a proof procedure | **Full re-run** — that procedure's proofs are already stale |
| Any change to `policy/coc.policy.d/` or `rules/` | **Full re-run** — the policy-set digest is in every decision |
| Re-vendoring `no-noodles` | **Full re-run**, and re-record the compat golden first |
| A new claim added to `docs/claims.yaml` | **Full re-run** — a new claim is unproven, so the gate is red until it is proved |
| Docs, README, the project page | Not required, but harmless |
| A bug fix in anything else in the repo | **Full re-run.** If you are asking whether it counts, it counts. |

---

## The sequence

Run from the repo root with the chain key available. **Do not skip a step, and do not reorder.**

```bash
export STOP_GUESSING_CHAIN_KEY="$(security find-generic-password -s stop-guessing-chain-key -a "$USER" -w)"
#   or --keyfile /path/to/key (mode 600). An unkeyed ledger cannot produce a proof, and
#   `prove` refuses rather than producing a weaker one silently.

# 0. The fix itself, with its test. Never weaken a test to get green.
ruff check .
pytest -m ""

# 1. If the vendored tree or the corpus changed, re-record the golden FIRST and read the diff.
#    A golden diff is a finding: either upstream changed or the dispatcher diverged.
stop-guessing manifest
stop-guessing compat verify              # compare; only --record-golden after reading the diff

# 2. Re-prove. Everything, not just what you touched — a policy change moves every decision.
stop-guessing prove

# 3. The gate.
stop-guessing claims check               # must be N/N

# 4. Re-derive the answers FROM the new proofs.
stop-guessing caiq derive

# 5. Prove CLAIM-21 LAST. Its procedure does the fill and pins the workbook digest into the
#    proof record, which is what binds them. Do NOT run `caiq fill` after this: the fill would
#    produce a new digest that no proof pinned, and `attest --self` correctly refuses that as
#    "edited outside the pipeline". Found the hard way — see the note below.
stop-guessing prove --claim CLAIM-21

# 6. Re-resolve every evidence ref against the ledger.
stop-guessing caiq evidence

# 7. The single command that answers the goal.
stop-guessing attest --self              # must exit 0 and print GOAL MET
```

**Ordering is load-bearing, not stylistic.** `caiq fill` and `prove --claim CLAIM-21` both write
the workbook, and only the proof records its digest. Running `fill` afterwards leaves a workbook
that no proof vouches for, and the attestation says so:

```
workbook bound     : False
  CAIQ FINDING     : the workbook changed since it was proven (proof pinned 8715893b…,
                     on disk e544fdf8…) - edited outside the pipeline, or re-derived
                     without re-proving
```

That is the gate working. The fix is to re-prove, never to re-fill.

Steps 4–6 exist as separate commands so each can be read, but they are one act: **the workbook is
regenerated from scratch every time.** There is no incremental update path, on purpose. An
incremental fill would let a stale answer survive a change that invalidated it.

---

## Verifying the gate still bites

A gate that cannot fail is not a gate, so **prove it can fail after every substantive change**.
Each of these must produce `GOAL NOT MET` or a named finding, and each was re-verified live:

```bash
cp .stop-guessing/proofs.jsonl /tmp/bak

# (a) truncate the proof ledger -> the truncated claims go unproven
head -n 30 /tmp/bak > .stop-guessing/proofs.jsonl
stop-guessing attest --self          # GOAL NOT MET, names the claims
cp /tmp/bak .stop-guessing/proofs.jsonl

# (b) hand-edit the filled workbook -> its digest no longer matches CLAIM-21's proof record
#     (flip a "No" to "Yes" — the tempting edit — then compare against the pinned digest)

# (c) edit the BODY of a proof procedure -> that claim's proofs are reported since-modified
stop-guessing claims check           # UNPROVEN <claim> !! produced by a since-modified procedure
```

**Note on (c):** the digest covers the *function*, not the file. A comment added at the end of
`procedures.py` does not invalidate 21 proofs, and should not — that granularity is deliberate. It
also means a weakened assertion inside a procedure body *does* invalidate it, which is the case
that matters.

---

## What "No" means here

The derived answers include deliberate **No** results (currently `LOG-12` and `STA-09`), each
stating the paths that were searched. Do not remove them to make the workbook look better.

- A questionnaire of unbroken Yeses is the least believable artifact an auditor can receive.
- `derive` will re-emit them from `NEGATIVE_ANSWERS` anyway.
- If a No becomes a Yes, it becomes one by *implementing the control and proving it*, then
  removing the entry from `NEGATIVE_ANSWERS` — in that order.

## What is never written into CSA's workbook

CSA's **draft agentic controls** — `IAM-AG-03`, `LOG-AG-01`, `LOG-AG-02` — are proposed on
labs.cloudsecurityalliance.org and do not exist in the published AICM v1.1.0. Their evidence is
real and is recorded under `proposed_agentic_controls:` in `docs/ai-caiq/stop-guessing.yaml`, and
`attest --self` reports it. They are **never** written into the workbook. `fill` refuses them, and
that refusal is what caught the first attempt.

## What is never modified

`AI_CAIQv1.1.0.xlsx` is a **copy-only local backup** of a CSA artifact. It is gitignored upstream
and **not recoverable from GitHub**. Every read is `read_only=True`; nothing saves; its digest is
pinned in `docs/ai-caiq/reference/TEMPLATE.json` and re-checked on every run. If the digest ever
mismatches, restore from one of the byte-identical copies named in `IMPLEMENTATION_PLAN.md` §12
and file an issue with the mismatching digest.

---

## Recording the run

The re-attestation is itself evidence. After a successful run:

1. Commit `docs/claims.yaml`, `docs/ai-caiq/stop-guessing.yaml` and the regenerated workbook
   together with the fix. They are one change.
2. Bump `VERSION` — every code-changing push gets a semver bump.
3. Append to `IMPLEMENTATION_LOG.md` if the change touched the chain format, the record schema,
   the risk engine or the vendored tree.
4. Reference the issue in the commit, and close it with the commit hash plus the
   `attest --self` output.

The proof ledger at `.stop-guessing/proofs.jsonl` is **not** committed — it is machine-local
evidence, and a ledger in git is a ledger anyone can rewrite in a branch. What is committed is the
set of record ids that must resolve against it, which is what makes a re-run necessary on any
machine that wants to verify the claims itself.
