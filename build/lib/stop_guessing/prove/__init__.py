"""Proving claims with this toolchain's own ledger.

The goal (IMPLEMENTATION_PLAN.md §2.1) is that every claim STOP-GUESSING makes is backed by a
proof it can point to using its own toolsets. A proof is a record in its own keyed ledger, not a
passing test — and `proofs:` in docs/claims.yaml is written only by `stop-guessing prove`.
"""
