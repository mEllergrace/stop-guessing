"""Exports. The custody record already speaks these vocabularies; these render it into them.

Deliberately serializers, not translators. The record carries `prov_type`, `gen_ai.*` and the
custody/evidence split natively, so an export is a projection rather than a re-interpretation —
which is the difference between a mapping that stays true and one that drifts.
"""
