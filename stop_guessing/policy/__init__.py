"""A Cedar-shaped policy decision point, in pure Python.

Cedar's `principal / action / resource / context` model maps cleanly onto
`agent identity / op / artifact / accumulated custody state`, and Cedar policies are statically
analysable — which matters for a CSA-branded control layer in a way it does not for a startup.

But `cedarpy` is a third-party compiled dependency, and this engine runs inside a PreToolUse hook
on every tool call. "Vendor the patterns, depend on nothing" wins: the model, the evaluation
order (`forbid` overrides `permit`, deny by default) and the schema shape are Cedar's; the
implementation is stdlib. `policy export --cedar` emits real Cedar for `cedar validate` in CI, and
a real-Cedar backend stays available when `cedarpy` imports.
"""
