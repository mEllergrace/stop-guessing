"""`stop-guessing page build` — render the project page from the attestation.

The page is generated, not written. Every number on it comes from `attest --self` and
`docs/claims.yaml`, so it cannot claim more than the ledger supports. A hand-written page that
says "21/21 proven" is a sentence someone typed; this one is a rendering of the same evidence the
auditor would read, and it goes stale loudly — `page check` fails in CI when the committed page
disagrees with the current attestation.

That is the same rule the AI-CAIQ follows, applied to marketing copy, which is where overclaiming
usually starts.
"""

from __future__ import annotations

import html
import json

from stop_guessing.attest.keys import from_env, from_keyfile
from stop_guessing.prove import runner
from stop_guessing.version import __version__, repo_root

PAGE = repo_root() / "docs" / "index.html"

CSS = """
:root{
  --ink:#12100e; --paper:#faf8f5; --muted:#6b625a; --rule:#e2dcd3; --rule-soft:#efeae3;
  --accent:#a8391f; --accent-soft:#f7ece8; --code-bg:#f2ede6;
  --ok:#2f6b4f; --ok-soft:#e8f2ec; --no:#8a6410; --no-soft:#f7f0dd;
  --mono:ui-monospace,"SF Mono",SFMono-Regular,Menlo,Consolas,monospace;
  --sans:-apple-system,BlinkMacSystemFont,"Segoe UI",Inter,Helvetica,Arial,sans-serif;
}
@media (prefers-color-scheme:dark){:root{
  --ink:#ece7e0; --paper:#12100e; --muted:#9d938a; --rule:#2c2723; --rule-soft:#211d1a;
  --accent:#e87d5f; --accent-soft:#2a1c16; --code-bg:#1c1917;
  --ok:#7fbf9c; --ok-soft:#16241d; --no:#d9ab52; --no-soft:#251e10;
}}
:root[data-theme="dark"]{
  --ink:#ece7e0; --paper:#12100e; --muted:#9d938a; --rule:#2c2723; --rule-soft:#211d1a;
  --accent:#e87d5f; --accent-soft:#2a1c16; --code-bg:#1c1917;
  --ok:#7fbf9c; --ok-soft:#16241d; --no:#d9ab52; --no-soft:#251e10;
}
:root[data-theme="light"]{
  --ink:#12100e; --paper:#faf8f5; --muted:#6b625a; --rule:#e2dcd3; --rule-soft:#efeae3;
  --accent:#a8391f; --accent-soft:#f7ece8; --code-bg:#f2ede6;
  --ok:#2f6b4f; --ok-soft:#e8f2ec; --no:#8a6410; --no-soft:#f7f0dd;
}
*{box-sizing:border-box}
html{scroll-behavior:smooth}
body{margin:0;background:var(--paper);color:var(--ink);font-family:var(--sans);
  font-size:17px;line-height:1.65;-webkit-font-smoothing:antialiased}
.wrap{max-width:46rem;margin:0 auto;padding:0 1.5rem 6rem}
header{padding:4.5rem 0 2.5rem}
h1{font-family:var(--mono);font-size:clamp(2rem,7vw,3rem);letter-spacing:-.03em;
  margin:0 0 .5rem;font-weight:600}
h1 .stop{color:var(--accent)}
.tagline{font-size:1.2rem;color:var(--muted);margin:0 0 1.75rem;max-width:34rem}
h2{font-size:1.05rem;font-family:var(--mono);font-weight:600;letter-spacing:-.01em;
  margin:3.5rem 0 1rem;padding-bottom:.4rem;border-bottom:1px solid var(--rule)}
h3{font-size:1rem;margin:1.75rem 0 .5rem}
p{margin:0 0 1.1rem}
a{color:var(--accent);text-decoration:none;border-bottom:1px solid transparent}
a:hover{border-bottom-color:var(--accent)}
code{font-family:var(--mono);font-size:.86em;background:var(--code-bg);
  padding:.12em .35em;border-radius:3px}
pre{background:var(--code-bg);border:1px solid var(--rule-soft);border-radius:5px;
  padding:1rem 1.1rem;overflow-x:auto;font-family:var(--mono);font-size:.82rem;line-height:1.6;
  margin:1.25rem 0}
pre code{background:none;padding:0;font-size:inherit}
blockquote{margin:1.5rem 0;padding:1rem 1.25rem;background:var(--accent-soft);
  border-left:3px solid var(--accent);border-radius:0 4px 4px 0}
blockquote p:last-child{margin:0}
.attest{border:1px solid var(--rule);border-radius:6px;overflow:hidden;margin:0 0 1rem}
.attest-top{background:var(--ok-soft);padding:1rem 1.25rem;border-bottom:1px solid var(--rule)}
.verdict{font-family:var(--mono);font-weight:600;color:var(--ok);font-size:1.05rem;
  display:flex;align-items:center;gap:.6rem;flex-wrap:wrap}
.verdict .cmd{color:var(--muted);font-weight:400;font-size:.8rem}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(8.5rem,1fr));gap:0;
  border-top:1px solid var(--rule-soft)}
.stat{padding:.9rem 1.25rem;border-right:1px solid var(--rule-soft);
  border-bottom:1px solid var(--rule-soft)}
.stat .n{font-family:var(--mono);font-size:1.45rem;font-weight:600;display:block;line-height:1.2}
.stat .l{font-size:.74rem;color:var(--muted);text-transform:uppercase;letter-spacing:.06em}
.caption{font-size:.85rem;color:var(--muted);margin:-.4rem 0 1.5rem}
.tablewrap{overflow-x:auto;margin:1.25rem 0}
table{border-collapse:collapse;width:100%;font-size:.9rem;min-width:28rem}
th,td{text-align:left;padding:.55rem .8rem;border-bottom:1px solid var(--rule-soft);
  vertical-align:top}
th{font-family:var(--mono);font-size:.74rem;text-transform:uppercase;letter-spacing:.05em;
  color:var(--muted);font-weight:600;border-bottom:1px solid var(--rule)}
td.mono,th.mono{font-family:var(--mono);font-size:.82rem;white-space:nowrap}
.tag{display:inline-block;font-family:var(--mono);font-size:.7rem;padding:.1rem .45rem;
  border-radius:3px;font-weight:600}
.tag.yes{background:var(--ok-soft);color:var(--ok)}
.tag.no{background:var(--no-soft);color:var(--no)}
ul,ol{padding-left:1.25rem;margin:0 0 1.1rem}
li{margin-bottom:.45rem}
.gap{border:1px solid var(--rule);border-radius:5px;padding:1.1rem 1.3rem;margin:1.25rem 0}
.gap h3{margin-top:0;font-family:var(--mono);font-size:.88rem;color:var(--accent)}
.gap p:last-child{margin-bottom:0}
footer{margin-top:5rem;padding-top:1.5rem;border-top:1px solid var(--rule);
  font-size:.86rem;color:var(--muted)}
.genstamp{font-family:var(--mono);font-size:.74rem;color:var(--muted);margin-top:.75rem}
"""


def _esc(s) -> str:
    return html.escape(str(s))


def build(attest: dict, claims: dict, caiq: dict | None) -> str:
    proven, total = attest["proven"], attest["total"]
    controls = attest["aicm_controls_evidenced"]
    refs = sum(len(c.get("proofs") or []) for c in claims["claims"])
    kinds: dict[str, int] = {}
    for c in claims["claims"]:
        kinds[c.get("proof_kind", "?")] = kinds.get(c.get("proof_kind", "?"), 0) + 1

    published = caiq["answers"] if caiq else []
    proposed = caiq["proposed_agentic_controls"]["answers"] if caiq else []
    yes = sum(1 for a in published if a["answer"] == "Yes")
    no = sum(1 for a in published if a["answer"] == "No")

    verdict = "GOAL MET" if attest["goal_met"] else "GOAL NOT MET"

    claim_rows = "\n".join(
        f'<tr><td class="mono">{_esc(c["id"])}</td>'
        f'<td class="mono">{_esc(c.get("proof_kind"))}</td>'
        f'<td>{_esc(c["statement"].strip())}</td>'
        f'<td class="mono">{len(c.get("proofs") or [])}</td></tr>'
        for c in claims["claims"]
    )

    control_rows = "\n".join(
        f'<tr><td class="mono">{_esc(ctrl)}</td>'
        f'<td class="mono">{_esc(", ".join(cl))}</td></tr>'
        for ctrl, cl in controls.items()
    )

    caiq_rows = "\n".join(
        f'<tr><td class="mono">{_esc(a["control"])}</td>'
        f'<td><span class="tag {"yes" if a["answer"] == "Yes" else "no"}">'
        f'{_esc(a["answer"])}</span></td>'
        f'<td class="mono">{len(a.get("evidence") or [])}</td>'
        f'<td class="mono">{_esc(", ".join(a.get("claims") or []))}</td></tr>'
        for a in published
    )

    proposed_names = ", ".join(a["control"] for a in proposed)

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>STOP-GUESSING — chain of custody for agentic AI</title>
<link rel="canonical" href="https://mellergrace.github.io/stop-guessing/">
<meta name="description" content="Chain of custody and data provenance for agentic AI. {proven} of {total} claims proven against its own keyed ledger; the AI-CAIQ is derived from those proofs.">
<meta name="theme-color" content="#12100e">
<meta property="og:type" content="website">
<meta property="og:site_name" content="STOP-GUESSING">
<meta property="og:url" content="https://mellergrace.github.io/stop-guessing/">
<meta property="og:title" content="STOP-GUESSING — chain of custody for agentic AI">
<meta property="og:description" content="Everything in this space records actions. Nothing records data flow. {proven}/{total} claims proven against its own keyed ledger.">
<meta name="twitter:card" content="summary">
<style>{CSS}</style>
</head>
<body>
<div class="wrap">

<header>
  <h1><span class="stop">STOP</span>-GUESSING</h1>
  <p class="tagline">Chain of custody and data provenance for agentic AI. It exists so that what
  an agentic tells you is not a guess.</p>

  <div class="attest">
    <div class="attest-top">
      <div class="verdict">{_esc(verdict)}
        <span class="cmd">stop-guessing attest --self · v{_esc(__version__)}</span></div>
    </div>
    <div class="grid">
      <div class="stat"><span class="n">{proven}/{total}</span><span class="l">claims proven</span></div>
      <div class="stat"><span class="n">{refs}</span><span class="l">ledger proofs</span></div>
      <div class="stat"><span class="n">{len(controls)}</span><span class="l">AICM controls</span></div>
      <div class="stat"><span class="n">{"keyed" if attest["chain_keyed"] else "unkeyed"}</span><span class="l">chain state</span></div>
    </div>
  </div>
  <p class="caption">Every number on this page is generated from that attestation, not typed.
  <code>stop-guessing page check</code> fails in CI when this page disagrees with the ledger.</p>
</header>

<h2>The problem</h2>

<p>An agent reads data, transforms it, reports a result — and nothing durable records which bytes
entered, what happened to them, or whether the report is true. Every downstream audit inherits
that gap.</p>

<p>Two documented failures define its shape. <strong>Replit / SaaStr</strong>, 21 July 2025: an
agent deleted a production database during an explicit code freeze, fabricated roughly 4,000
fictional records, and misreported what it had done
(<a href="https://incidentdatabase.ai/cite/1152/">AI Incident Database #1152</a>).
<strong>Berkeley RDI</strong>, April 2026: a zero-capability agent scored ~100% on eight benchmarks
by attacking the evaluator — including installing a fake <code>curl</code> that returned fabricated
success to the grader
(<a href="https://rdi.berkeley.edu/blog/trustworthy-benchmarks-cont/">writeup</a>).</p>

<p>The second is a design constraint, not an anecdote: <strong>the recorder must not be reachable
by the agent it records.</strong></p>

<h2>What nobody else does</h2>

<p>Everything in this space records <em>actions</em>. Nothing records <em>data flow</em>. Surveyed
across Claude Code's native OpenTelemetry, Obsigna, HDP, Langfuse, Arize Phoenix, LangSmith,
OpenLineage and Microsoft's agent-governance-toolkit: every one answers <em>“which agent called
which tool, and was it allowed?”</em> Not one answers <em>“which bytes entered, and where did they
end up?”</em></p>

<div class="gap">
<h3>Accumulation, not per-call matching</h3>
<p>Every agent DLP hook in the wild is a regex fired independently per call, and each call looks
fine. The risk that materialises is twelve individually-innocuous reads composing into a dataset,
then one egress. Proved across six separate hook processes:</p>
<pre><code>PROCESS 1: clean session, egress            -> allowed
PROCESSES 2-5: four classified reads        -> ask (each a separate process)
PROCESS 6: the IDENTICAL egress             -> DENY
  contributing artifacts: art_27607079, art_66617765, art_84867751, art_86402881</code></pre>
<p>The same <code>curl</code>, opposite answers. What changed is what the session carries.</p>
</div>

<div class="gap">
<h3>Derivation edges</h3>
<p>An output <em>declared public</em>, built from two restricted inputs, carries <code>restricted</code>
— with an edge per input naming the script that joined them. OpenTelemetry's GenAI semantic
conventions contain zero provenance attributes; OpenLineage has the right graph primitive and no
agent emitter.</p>
</div>

<div class="gap">
<h3>Custody state as a policy input</h3>
<p>No surveyed system feeds accumulated custody state back into the permission decision. The hooks
to do it are shipping, and unused. Here the session's taint is the <code>context</code> a
Cedar-shaped policy engine evaluates against.</p>
</div>

<h2>The thesis</h2>

<blockquote><p>The agent's control decisions are computed only from trusted inputs; data handling
is delegated to deterministic, capability-constrained code; and every delegation is
recorded.</p></blockquote>

<p>Backing: <a href="https://arxiv.org/abs/2506.08837">Design Patterns for Securing LLM Agents
against Prompt Injections</a> (IBM / Google / ETH / Microsoft) and
<a href="https://arxiv.org/abs/2503.18813">CaMeL</a> (DeepMind / ETH), which protect
<em>control flow</em> rather than sight of data. The stronger claim — that the model never sees
data — is what the <code>bar</code> posture implements. It ships as an option; it is not the claim
we lead with.</p>

<blockquote><p><strong>Provenance is evidentiary, not preventive.</strong> A hash-chained log of an
exfiltration is still an exfiltration. This is not a prompt-injection defence and will not be sold
as one.</p></blockquote>

<h2>What a proof is</h2>

<p>Not a passing test. A proof is a record in this toolchain's own <strong>keyed</strong> ledger,
produced by an executable procedure that exercises the real surface. <code>proofs:</code> in
<code>docs/claims.yaml</code> is written only by <code>stop-guessing prove</code>. A claim with no
surviving proof is a <strong>failed</strong> claim, not an unassessed one.</p>

<p>The chain is HMAC-keyed rather than a plain hash chain, because an agent with write access can
truncate a SHA-256 chain and recompute a valid one. Demonstrated and kept as a control test:</p>

<pre><code>unkeyed ledger, 50 records fabricated -> intact=True   &lt;-- forgery UNDETECTED
keyed,  forged with no key            -> caught at entry 100
keyed,  forged with wrong hmac key    -> caught at entry 100
keyed,  forged WITH the real key      -> intact  (the key is what stops it)</code></pre>

<h3>A gate that cannot fail is not a gate</h3>
<p>Each of these is verified after every change, and each produces a named finding:</p>
<ul>
<li>Tamper with a proof record → the chain breaks and <strong>every</strong> proof in it is invalidated</li>
<li>Hand-edit a real record id onto another claim → <code>was recorded against CLAIM-02</code></li>
<li>Edit a procedure body after it proved something → <code>produced by a since-modified procedure</code></li>
<li>Hand-edit the filled workbook → its digest no longer matches the one pinned in the proof</li>
</ul>

<h2>Claims</h2>
<div class="tablewrap"><table>
<thead><tr><th class="mono">id</th><th class="mono">kind</th><th>claim</th><th class="mono">proofs</th></tr></thead>
<tbody>
{claim_rows}
</tbody></table></div>
<p class="caption">Proof kinds: {_esc(", ".join(f"{k} {v}" for k, v in sorted(kinds.items())))}.
Negative and adversarial procedures are not optional — a toolchain that proves only its happy
paths has proven nothing an auditor wants.</p>

<h2>AICM coverage</h2>
<div class="tablewrap"><table>
<thead><tr><th class="mono">control</th><th class="mono">evidenced by</th></tr></thead>
<tbody>
{control_rows}
</tbody></table></div>

<h2>The carried AI-CAIQ</h2>

<p>The workbook is a <strong>rendering of the ledger</strong>, not an input to it. Answers are
computed from the claims that are proven and the records that proved them, and the fill runs
last. Filling first and hunting for evidence afterwards is the failure
<code>rockin-robin</code>'s own conformance-gap document names: <em>“that is a STRING IN A PROMPT,
not conformance.”</em></p>

<div class="tablewrap"><table>
<thead><tr><th class="mono">control</th><th class="mono">answer</th><th class="mono">evidence</th><th class="mono">from claims</th></tr></thead>
<tbody>
{caiq_rows}
</tbody></table></div>

<p class="caption">{yes} Yes, {no} No. The No answers state the paths that were searched — a
questionnaire of unbroken Yeses is the least believable artifact an auditor can receive.
Output passes rich-text's <code>verify_ai_caiq_workbook.py</code> unmodified, and CSA's blank
template is copy-only: read <code>read_only=True</code>, never saved, digest re-checked every run.</p>

<p><strong>Not written into CSA's workbook:</strong> {_esc(proposed_names)}. These are CSA's
<em>draft</em> agentic controls from the labs space and do not exist in published AICM v1.1.0.
Their evidence is real and is recorded separately; presenting them as AICM rows would be
fabrication. The fill refuses them — which is how the first attempt was caught.</p>

<h2>Relationship to no-noodles</h2>

<p>STOP-GUESSING vendors <a href="https://github.com/moonsoup/no-noodles">no-noodles</a>
byte-identically and supersedes it. One dispatcher replaces four hook registrations and runs the
vendored rules first, in their original order, passing their refusals through byte-for-byte —
so a user who has learned what <code>NO-NOODLE:</code> looks like sees the same text.
<code># noodle-ok</code>, <code># risk-ok</code> and <code># build-ok:</code> keep working, as do
<code>/no-noodle</code> and <code>/noodle-options</code>. A 73-case corpus replayed through both
paths is the acceptance gate.</p>

<h2>Install</h2>
<pre><code>/plugin marketplace add mEllergrace/stop-guessing
/plugin install stop-guessing@stop-guessing

# or, for the supersession path and tier-2 isolation
git clone https://github.com/mEllergrace/stop-guessing
cd stop-guessing &amp;&amp; ./install.sh --all-profiles --supersede-no-noodles</code></pre>

<p>Three postures ship; the default is <code>steer</code>. Full-depth tracking is the default and
is never silently reduced. Removable at four levels — posture, per-rule, per-project, full
uninstall — none of which destroys the accumulated ledger.</p>

<p><strong>Offline by default.</strong> No runtime path makes an external network call; the
package is audited for call sites rather than asserted to be clean. Sigstore and RFC 3161
anchoring are opt-in and announce themselves.</p>

<footer>
<p><a href="https://github.com/mEllergrace/stop-guessing">github.com/mEllergrace/stop-guessing</a>
· Apache-2.0 · aligned to CSA AICM v1.1.0 · <a
href="https://github.com/mEllergrace/stop-guessing/blob/main/IMPLEMENTATION_PLAN.md">implementation
plan</a> · <a
href="https://github.com/mEllergrace/stop-guessing/blob/main/docs/REATTESTATION.md">re-attestation
runbook</a></p>
<p class="genstamp">Generated by <code>stop-guessing page build</code> from the attestation.
Not hand-written.</p>
</footer>

</div>
</body>
</html>
"""


def _key(args):
    if getattr(args, "keyfile", None):
        got = from_keyfile(args.keyfile)
        if got:
            return got[0]
    got = from_env()
    return got[0] if got else None


class NoChainKey(Exception):
    """Cannot render or check without the key.

    Rendering unkeyed would silently produce a page reporting 0/21 — technically what an unkeyed
    verifier can see, and a lie about the project. `prove` refuses for the same reason; so does
    this. A gate that cannot verify must say so, not quietly disagree.
    """


def _render(args) -> str:
    import yaml

    key = _key(args)
    if key is None:
        raise NoChainKey(
            "no chain key available. Without it the attestation reports 0 proven, and a page "
            "rendered from that would misstate the project. Set STOP_GUESSING_CHAIN_KEY or "
            "pass --keyfile."
        )
    attest = runner.attest_self(key)
    claims = runner.load_claims()
    caiq_path = repo_root() / "docs" / "ai-caiq" / "stop-guessing.yaml"
    caiq = yaml.safe_load(caiq_path.read_text(encoding="utf-8")) if caiq_path.is_file() else None
    return build(attest, claims, caiq)


def cmd_build(args) -> int:
    try:
        html_out = _render(args)
    except NoChainKey as exc:
        print(f"REFUSED: {exc}")
        return 2
    PAGE.write_text(html_out, encoding="utf-8")
    print(f"wrote {PAGE.relative_to(repo_root())} ({len(html_out)} bytes)")
    return 0


def cmd_check(args) -> int:
    """CI gate: the committed page must match what the ledger currently supports."""
    if not PAGE.is_file():
        print("FAIL: docs/index.html is missing")
        return 1
    current = PAGE.read_text(encoding="utf-8")
    try:
        expected = _render(args)
    except NoChainKey as exc:
        print(f"SKIPPED: {exc}")
        return 2
    if current == expected:
        print("PASS: the page matches the current attestation")
        return 0
    print("FAIL: docs/index.html disagrees with the current attestation.")
    print("      Run `stop-guessing page build` and commit the result.")
    print("      A page that outlives the evidence it cites is how overclaiming starts.")
    return 1


def register(sub) -> None:
    p = sub.add_parser("page", help="the project page, generated from the attestation")
    s = p.add_subparsers(dest="page_cmd", required=True)
    for name, fn, helptext in (("build", cmd_build, "render docs/index.html"),
                               ("check", cmd_check, "fail if the page is stale")):
        sp = s.add_parser(name, help=helptext)
        sp.add_argument("--keyfile")
        sp.set_defaults(fn=fn)


def _json_dump(obj) -> str:  # pragma: no cover - debugging aid
    return json.dumps(obj, indent=2)
