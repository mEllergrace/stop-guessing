"""Tamper-evident, keyed, append-only custody ledger.

`chain` and `alerts` are pure. `sink` and `segments` are the only modules that touch the
filesystem, so all IO risk is confined and the interesting logic stays testable without one.
"""
