---
name: custody
description: Inspect the chain-of-custody ledger, prove claims, and attest this toolchain against AICM.
---

# /custody

STOP-GUESSING — chain of custody and data provenance for agentic AI.

```
stop-guessing ledger verify          # is the chain intact, and was it verified under its key?
stop-guessing ledger tail -n 20      # recent records
stop-guessing ledger alerts          # what a human should look at, chain first
stop-guessing verify --sufficiency   # does this ledger answer a governance question?
stop-guessing claims check           # the release gate
stop-guessing attest --self          # claims -> proofs -> AICM controls, in one command
```

**A proof is a ledger record id, not a passing test.** `proofs:` in `docs/claims.yaml` is written
only by `stop-guessing prove`. A claim with no surviving proof is a FAILED claim, not an
unassessed one.

**Verifying without the key reports `chain-only`, never "tamper-proof".** Say what was checked.
