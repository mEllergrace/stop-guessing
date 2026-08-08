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

from stop_guessing.attest.keys import discover, keyid_of_ledger, same_key
from stop_guessing.prove import runner
from stop_guessing.version import __version__, repo_root

PAGE = repo_root() / "docs" / "index.html"
README = repo_root() / "README.md"

BEGIN = "<!-- BEGIN GENERATED STATUS -->"
END = "<!-- END GENERATED STATUS -->"

# The framework posture is generated for the same reason the status block is: it was hand-written,
# it drifted, and a hand-written conformance claim is the one thing this project must not ship. The
# tiers come from docs/frameworks.yaml, whose `externally-validated` rows are checked against
# scripts/benchmark_frameworks.py by tests/test_frameworks_posture.py — so the published claim cannot
# outrun the measurement.
FW_BEGIN = "<!-- BEGIN GENERATED FRAMEWORKS -->"
FW_END = "<!-- END GENERATED FRAMEWORKS -->"

TIER_LABEL = {
    "externally-validated": ("Externally validated",
                             "a third party's validator returns a verdict on our output, and a "
                             "control confirms it rejects a deliberately broken input"),
    "self-asserted": ("Self-asserted",
                      "our own tests check our own reading of the spec — honest, and weaker"),
    "mapped": ("Mapped",
               "clauses or controls tied to evidence. A mapping is not a conformance assessment"),
    "design-target": ("Design target",
                      "it shaped the build; no clause-by-clause mapping exists"),
    "not-benchmarked": ("Not benchmarked",
                        "a framework a competent reviewer would expect, named with why it is absent"),
    "out-of-scope": ("Out of scope", "deliberately not pursued, with the reason"),
}
TIER_ORDER = list(TIER_LABEL)


def _frameworks_doc() -> dict:
    import yaml

    path = repo_root() / "docs" / "frameworks.yaml"
    return yaml.safe_load(path.read_text(encoding="utf-8")) if path.is_file() else {"frameworks": []}


def frameworks_markdown() -> str:
    """The posture, as markdown, generated from docs/frameworks.yaml."""
    doc = _frameworks_doc()
    rows = doc.get("frameworks") or []
    if not rows:
        return f"{FW_BEGIN}\n_no framework posture recorded_\n{FW_END}"

    counts = {t: len([r for r in rows if r["tier"] == t]) for t in TIER_ORDER}
    out = [FW_BEGIN, "",
           "**\"Aligned to\" is not \"benchmarked against.\"** This table keeps the two apart, and it "
           "is generated from [`docs/frameworks.yaml`](docs/frameworks.yaml) — whose "
           "externally-validated rows are checked against the actual validator output by "
           "`tests/test_frameworks_posture.py`, so a claim here cannot outrun its measurement.", "",
           f"**{counts['externally-validated']} externally validated · "
           f"{counts['self-asserted']} self-asserted · {counts['mapped']} mapped · "
           f"{counts['design-target']} design targets · "
           f"{counts['not-benchmarked']} named but not benchmarked · "
           f"{counts['out-of-scope']} out of scope**", ""]

    for tier in TIER_ORDER:
        group = [r for r in rows if r["tier"] == tier]
        if not group:
            continue
        label, meaning = TIER_LABEL[tier]
        out += [f"### {label}", "", f"*{meaning}.*", ""]
        if tier == "externally-validated":
            out += ["| Framework | Validator | Result | Control |", "|---|---|---|---|"]
            for r in group:
                out.append(f"| **{r['name']}** | `{r.get('validator','')}` | "
                           f"{_one_line(r.get('result'))} | {_one_line(r.get('control'))} |")
        elif tier == "not-benchmarked":
            out += ["Ranked by value. Each carries what else was weighed and a **review trigger** — a "
                    "condition, not a date, because a standards choice written once as prose becomes "
                    "the constraint the next reader inherits.", "",
                    "| # | Framework | Why it matters, and when to look again |", "|---|---|---|"]
            for r in sorted(group, key=lambda x: x.get("priority", 99)):
                cell = _one_line(r.get("why") or r.get("what"))
                if r.get("scope_limit"):
                    cell += f" **Scope limit:** {_one_line(r['scope_limit'])}"
                if r.get("alternatives_considered"):
                    cell += f" *Weighed against:* {_one_line(r['alternatives_considered'])}"
                if r.get("review"):
                    cell += f" **Review when:** {_one_line(r['review'])}"
                out.append(f"| {r.get('priority', '')} | **{r['name']}** | {cell} |")
        elif tier == "out-of-scope":
            out += ["| Framework | Why it is not here |", "|---|---|"]
            for r in group:
                out.append(f"| **{r['name']}** | {_one_line(r.get('why') or r.get('what'))} |")
        else:
            out += ["| Framework | What is claimed, exactly |", "|---|---|"]
            for r in group:
                detail = _one_line(r.get("result") or r.get("what"))
                if r.get("gap"):
                    detail += f" **Gap:** {_one_line(r['gap'])}"
                out.append(f"| **{r['name']}** | {detail} |")
        out.append("")
    out.append(FW_END)
    return "\n".join(out)


def _one_line(text) -> str:
    if not text:
        return ""
    return " ".join(str(text).split()).replace("|", "\\|")

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
    FRAMEWORKS_HTML = frameworks_html()
    proven, total = attest["proven"], attest["total"]
    controls = attest["aicm_controls_evidenced"]
    # SG-HARD-053: current live evidence, not every historical re-run. See readme_status().
    refs = sum(len(r.get("live") or []) for r in attest.get("rows") or [])
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

    j = attest.get("judge") or {}
    if j:
        rows = "\n".join(
            f'<tr><td class="mono">{_esc(lens)}</td><td class="mono">{n}</td></tr>'
            for lens, n in (j.get("by_lens") or {}).items())
        judge_block = (
            '<div class="tablewrap"><table>'
            '<thead><tr><th class="mono">lens</th>'
            '<th class="mono">deferred disapprovals</th></tr></thead>'
            f"<tbody>{rows}</tbody></table></div>"
            f"<p>{j['claims_judged']} claims, {j['verdicts']} verdicts, "
            f"<strong>{j['deferred_disapprovals']} deferred disapproval(s)</strong>.</p>"
        )
    else:
        judge_block = "<p>No judge panel has run.</p>"

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
  <p class="caption">Every number on this page is generated from that attestation, not typed —
  <code>stop-guessing page check</code> refuses to render when it cannot verify. But read the next
  paragraph before reading the numbers.</p>

  <p class="caption"><a href="https://github.com/mEllergrace/stop-guessing">Repository</a> ·
  <a href="ai-caiq/AI-CAIQ-stop-guessing-v1.1.0.xlsx">Carried AI-CAIQ</a>
  (<a href="ai-caiq/stop-guessing.yaml">source</a>) ·
  <a href="claims.yaml">Claims and their proofs</a> ·
  <a href="#where-the-ledgers-are">Where the ledgers are</a> ·
  <a href="#reading-them">Reading them</a><br>
  The AI-CAIQ is rendered from the proof records and never written by hand: a control answers
  <code>Yes</code> only where a ledger record supports it. The ledger itself is not published here —
  it is per-install evidence rather than a document, and records the absolute paths of the machine
  that produced it. Yours is the only one that says anything about your work.</p>

  <blockquote><p><strong>This is self-attestation, not independent certification.</strong> The
  claims are proven by procedures in this repository against a ledger on the maintainer's machine.
  Nobody else has verified them, no auditor has sampled them, and CSA has not assessed this tool.
  <code>page check</code> runs where the chain key lives; in ordinary GitHub Actions it has no key
  and <em>skips</em> — so CI does not enforce this page's freshness.</p></blockquote>
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

<h2>What is and is not proven</h2>

<p>An independent review on 2026-08-03 found that the proof harness could demonstrate a primitive
while the installed plugin never invoked it — and it was right about eighteen findings, filed as
<a href="https://github.com/mEllergrace/stop-guessing/issues?q=label%3Aexternal-review">#13&ndash;#30</a>.
The distinction it drew is the one that matters here:</p>

<div class="tablewrap"><table>
<thead><tr><th>Proven</th><th>Not proven</th></tr></thead>
<tbody>
<tr><td>The keyed ledger detects truncate-and-recompute; an unkeyed one does not</td>
    <td>That any third party has verified any of this</td></tr>
<tr><td>The installed hook writes keyed custody records at PreToolUse and PostToolUse</td>
    <td>That the recorder is beyond the agent's reach — there is no daemon, so isolation stays at
        tier 0/1</td></tr>
<tr><td>Taint survives process boundaries and cache deletion, because the ledger is authoritative</td>
    <td>That egress detection is complete — it is a command-shape heuristic, not a boundary</td></tr>
<tr><td>Derivation edges carry labels from inputs to outputs</td>
    <td>That path extraction sees every artifact a shell command touches</td></tr>
<tr><td>Segment seals are MAC'd, so history cannot be rewritten without the key</td>
    <td>That delegated scripts are sandboxed — "network=deny" is proxy variables, not a capability
        boundary</td></tr>
<tr><td>The AI-CAIQ is derived from proofs and the template is never modified</td>
    <td>That signing is publicly verifiable — it is HMAC, so a verifier needs the signing key</td></tr>
</tbody></table></div>

<h2>What the judge panel says</h2>

<p>A panel of mechanical lenses reviews each proof procedure for <em>adequacy</em> — whether the
test inside it is strong, not merely whether it ran. Disapproval is <strong>deferred</strong>: it is
recorded in the ledger and shown here, and it does not flip the verdict. A heuristic is qualified to
make a human look, not to void a proof.</p>

{judge_block}

<p class="caption">The <code>independence</code> lens dissents on every claim and always will. The
claim, the procedure and the panel share one author, so no independent party has verified any of
this. That is the gap, stated rather than averaged away.</p>

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

{FRAMEWORKS_HTML}
<h2>Relationship to no-noodles</h2>

<p>STOP-GUESSING vendors <a href="https://github.com/moonsoup/no-noodles">no-noodles</a>
byte-identically and supersedes it. One dispatcher replaces four hook registrations and runs the
vendored rules first, in their original order, passing their refusals through byte-for-byte —
so a user who has learned what <code>NO-NOODLE:</code> looks like sees the same text.
<code># noodle-ok</code>, <code># risk-ok</code> and <code># build-ok:</code> keep working, as do
<code>/no-noodle</code> and <code>/noodle-options</code>. A 73-case corpus replayed through both
paths is the acceptance gate.</p>

<h2>Install and remove</h2>
<pre><code>/plugin marketplace add mEllergrace/stop-guessing
/plugin install stop-guessing@stop-guessing

# or, for the supersession path and tier-2 isolation
git clone https://github.com/mEllergrace/stop-guessing
cd stop-guessing &amp;&amp; ./install.sh --profile ~/.claude

./install.sh --dry-run      # print the exact settings.json diff, change nothing
./install.sh --uninstall    # remove hooks and registrations</code></pre>

<p><code>--all-profiles</code> installs into every <code>~/.claude*</code> holding a
<code>settings.json</code>; <code>--supersede-no-noodles</code> removes standalone no-noodles
PreToolUse entries so the dispatcher runs the vendored rules in their original order;
<code>--isolated</code> runs the recorder under its own uid. Every write backs up
<code>settings.json</code> beside itself.</p>

<p><strong><code>--uninstall</code> preserves your evidence.</strong> Hooks and registrations go;
the ledger, state and observations stay exactly where they are. Removing a recorder should not
destroy what it recorded.</p>

<h2 id="where-the-ledgers-are">Where the ledgers are</h2>
<p>Two files, keyed independently — one verifying tells you nothing about the other. Both are
project-local, so evidence sits beside the work it describes and is attributable by construction.</p>
<pre><code>&lt;project&gt;/.stop-guessing/ledger/custody.jsonl   what the hooks recorded
&lt;project&gt;/.stop-guessing/proofs.jsonl           the records every claim cites</code></pre>

<p><code>$STOP_GUESSING_HOME</code> overrides that for a deliberately shared store. Installs
predating 0.6.1 wrote under <code>$CLAUDE_CONFIG_DIR</code>; that location is still read and still
reported by <code>doctor</code>. Nothing was moved — relocating evidence without recording the move
is the alteration this project refuses to perform silently.</p>

<h2 id="reading-them">Reading them</h2>
<pre><code>stop-guessing ledger verify          # intact, and verified under its key?
stop-guessing ledger tail -n 20      # recent records
stop-guessing ledger alerts          # what a human should look at, chain first
stop-guessing doctor                 # install, recorder, posture, and which layer set it
stop-guessing verify --sufficiency   # does this ledger answer a governance question?
stop-guessing export prov|case|otel  # W3C PROV, CASE/UCO, or OpenTelemetry</code></pre>

<p>Verifying without the key reports <code>chain-only</code>, never "tamper-proof": the chain shape
can be checked by anyone, that the records are yours cannot, and the two are reported separately
rather than blended. <code>export</code> refuses on a ledger that does not verify — rendering
unverifiable records into an authoritative-looking format is laundering, not exporting.</p>

<h2>Switching recording on and off</h2>
<p>Three scopes. Prefer the smallest that covers what you mean: reaching for a machine-wide switch
to serve a per-project intent is how one project's preference becomes everyone's.</p>
<pre><code>./.stop-guessing.json                     {{"record": false}}   one project
$CLAUDE_CONFIG_DIR/stop-guessing.json     {{"record": false}}   one profile
STOP_GUESSING_DISABLE=1                                       everywhere</code></pre>
<p>Absent means on, and every hook honours it rather than the gate alone. Whichever scope you use,
the transition is written to the ledger once — absence of records must never be readable as absence
of activity.</p>

<h2>The options</h2>
<p>All of these live in <code>.stop-guessing.json</code>, project-local or in the profile, resolved
project-first. <code>/custody-options</code> documents the same set from inside a session, and
<code>stop-guessing doctor</code> reports which layer is actually deciding.</p>
<table>
<thead><tr><th>Key</th><th>Values</th><th>Effect</th></tr></thead>
<tbody>
<tr><td class="mono">posture</td><td class="mono">observe · steer · bar</td><td>how much the gate
may interrupt. <code>observe</code> is the default: records everything, asks nothing, because the
host already has a permission model its operator configured and a second gate asking again is a
recorder overriding a decision its user has already made</td></tr>
<tr><td class="mono">record</td><td class="mono">true · false</td><td>whether this project is
recorded at all</td></tr>
<tr><td class="mono">protect_ledger</td><td class="mono">true · false</td><td>refuse writes to the
evidence ledger itself — the one refusal that outlives every posture</td></tr>
<tr><td class="mono">no_ad_hoc_probes<br>check_before_build<br>risk_scoring</td><td class="mono">no-noodles
keys</td><td>unchanged, and still read from <code>.no-noodles.json</code> too</td></tr>
</tbody>
</table>
<p><code>$CLAUDE_CONFIG_DIR/managed.json</code> sits above all of it as a floor an operator sets
outside project write authority. A project may tighten past it and is ignored where it would loosen,
so the party being recorded cannot weaken the policy it is recorded under. Full-depth tracking is the
default and is never silently reduced; nothing here destroys the accumulated ledger.</p>

<p><strong>Offline by default.</strong> The shipped package is audited for network call sites and
has none outside the named opt-in anchoring exception. That is a source audit, not proof of no
network activity — it cannot see indirect subprocess calls, shell programs or commands assembled at
runtime. Sigstore and RFC 3161 anchoring are opt-in and announce themselves.</p>

<footer>
<p><a href="https://github.com/mEllergrace/stop-guessing">github.com/mEllergrace/stop-guessing</a>
· <a href="ai-caiq/AI-CAIQ-stop-guessing-v1.1.0.xlsx">carried AI-CAIQ</a>
(<a href="ai-caiq/stop-guessing.yaml">source</a>)
· <a href="claims.yaml">claims and their proofs</a>
· <a href="#where-the-ledgers-are">where the ledgers are</a>
· <a href="REATTESTATION.md">re-attestation runbook</a>
· Apache-2.0 · aligned to CSA AICM v1.1.0</p>
<p class="genstamp">Generated by <code>stop-guessing page build</code> from the attestation.
Not hand-written.</p>
</footer>

</div>
</body>
</html>
"""


AUDIT_STATUS = "docs/audit-status.json"


def _audit_limits(top: int = 6) -> str:
    """The gate's own outstanding limits, rendered from the verifier rather than typed.

    This block was hand-written for one commit and was stale by the next: it listed three findings
    as outstanding that had already been fixed. A section whose whole purpose is honesty cannot be
    the one part of the README that rots, so it is generated from `docs/audit-status.json`, which
    `scripts/audit_verify.py --json` produces. Fixed findings leave the list by themselves.
    """
    import json as _json

    p = repo_root() / AUDIT_STATUS
    try:
        doc = _json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return ("**What this gate does not establish**: `docs/audit-status.json` is missing, so "
                "this cannot be stated. Run `scripts/audit_verify.py --json > docs/audit-status.json`.")

    rows = doc.get("findings") or []
    present = [r for r in rows if r["status"] == "PRESENT"]
    dynamic = [r for r in rows if r["status"] == "DYNAMIC"]
    fixed = [r for r in rows if r["status"] == "ABSENT"]
    crit = [r for r in present if r["severity"] == "CRITICAL"]

    shown = (crit or present)[:top]
    bullets = "\n".join(
        f"- {r['title']} ({r['id']})" for r in shown
    ) or "- none outstanding"
    more = len(crit or present) - len(shown)

    return f"""**What this gate does not establish.** An independent hardening audit on 2026-08-04
raised 54 findings. Each was re-verified against source rather than accepted; the current state,
generated from [`{AUDIT_STATUS}`]({AUDIT_STATUS}) at commit `{doc.get('commit', '?')}`, is
**{len(present)} confirmed outstanding, {len(fixed)} fixed, {len(dynamic)} unverified** (no static
predicate — those need a live adversarial test and are not counted as passing).

{'Outstanding CRITICAL findings' if crit else 'Outstanding findings'}:

{bullets}
{f"- …and {more} more — see the `hardening-audit` label." if more > 0 else ""}

Re-derive any of it with `scripts/audit_verify.py --id <id>`; the predicate reports only whether
the defect is still present.
"""


def readme_status(attest: dict, claims: dict, caiq: dict | None) -> str:
    """The README's status block, generated for the same reason the page is.

    The README said "planning complete, implementation not started" for nine code-changing
    commits after that stopped being true. Prose rots; a rendering of the ledger does not.
    """
    proven, total = attest["proven"], attest["total"]
    # SG-HARD-053: this used to sum every ref ever recorded, including superseded re-runs, while
    # runner.check() counts only the latest surviving proof per claim. That inflated the headline
    # with repetition — 134 "records" where most were the same procedures re-run. Current live
    # evidence and historical runs are now reported as the different things they are.
    live = sum(len(r.get("live") or []) for r in attest.get("rows") or [])
    superseded = sum(len(r.get("superseded") or []) for r in attest.get("rows") or [])
    controls = attest["aicm_controls_evidenced"]
    published = caiq["answers"] if caiq else []
    yes = sum(1 for a in published if a["answer"] == "Yes")
    no = sum(1 for a in published if a["answer"] == "No")
    kinds: dict[str, int] = {}
    for c in claims["claims"]:
        kinds[c.get("proof_kind", "?")] = kinds.get(c.get("proof_kind", "?"), 0) + 1
    kind_str = ", ".join(f"{v} {k}" for k, v in sorted(kinds.items()))

    # SG-HARD-041 / 044: "GOAL MET" collapsed execution, adequacy and independent verification into
    # one flattering boolean. An independent hardening audit on 2026-08-04 established that the gate
    # producing it does not validate a claim's declared surface, survives a deleted procedure and a
    # truncated ledger, and that the workbook it binds is written one epoch behind its own proof.
    # The evidence is real; the headline it carried was not, so the headline is what changes.
    verdict = ("self-attested" if attest["goal_met"] else "SELF-ATTESTATION INCOMPLETE")

    # #74 (SG-HARD-041): compare like with like. The workbook counts APPLICATION claims, because
    # the release-attestation claim's own procedure writes the file and its proof record does not
    # exist yet at that moment. Comparing that against the all-claims total made the two artifacts
    # disagree by exactly one, permanently and by construction. A remaining mismatch after this
    # correction is a real staleness finding, so it is still reported — just not manufactured.
    caiq_epoch = ""
    if caiq and (caiq.get("meta") or {}).get("claims_proven"):
        from stop_guessing.caiq.answers import RELEASE_ATTESTATION_CLAIMS

        epoch = caiq["meta"]["claims_proven"]
        app_rows = [r for r in (attest.get("rows") or [])
                    if r["id"] not in RELEASE_ATTESTATION_CLAIMS]
        expected = f"{sum(1 for r in app_rows if r.get('proven'))}/{len(app_rows)}"
        if epoch != expected:
            caiq_epoch = (
                f"\n> **The carried workbook reports `{epoch}` application claims, but the current "
                f"attestation derives `{expected}`.** The workbook is stale — re-run "
                f"`stop-guessing prove --claim {sorted(RELEASE_ATTESTATION_CLAIMS)[0]}` to "
                f"regenerate and re-pin it.\n"
            )

    return f"""{BEGIN}
**Version {__version__} — `stop-guessing attest --self` reports {verdict}: {proven}/{total} claims
executed, witnessed and chain-verified on the maintainer's machine.**

**This is self-attestation. It has not been independently verified, and the gate that produces it
has known limits — stated here rather than in a subsection, because a reader who stops at the
headline is exactly who they matter to.**
{caiq_epoch}
| | |
|---|---|
| Claims executed | **{proven}/{total}**, by {live} current ledger record(s){f" ({superseded} superseded re-run(s) not counted)" if superseded else ""} |
| Proof kinds | {kind_str} — negative and adversarial are not optional |
| AICM controls evidenced | {len(controls)} |
| Chain | intact, {"keyed-verified" if attest["chain_keyed"] else "NOT keyed-verified"} |
| Carried AI-CAIQ | {len(published)} published controls answered ({yes} Yes, {no} No), derived from those proofs |
| Judge panel | {(attest.get("judge") or {}).get("deferred_disapprovals", "?")} deferred disapprovals, recorded not blocking — including `independence` on every claim |

{_audit_limits()}
A **proof** is a record in this toolchain's own ledger, produced by a procedure that exercises the
real surface — not a passing test. `proofs:` in [`docs/claims.yaml`](docs/claims.yaml) is written
only by `stop-guessing prove`. A claim with no surviving proof is a **failed** claim, not an
unassessed one.

This block is generated by `stop-guessing page build` and checked by `stop-guessing page check`.
It said "implementation not started" for nine commits after that stopped being true, which is why
it is no longer written by hand.
{END}"""


def _key(args):
    """The chain key, resolved the way the rest of the CLI resolves it.

    #90, third instance. This looked at `--keyfile` and then `$STOP_GUESSING_CHAIN_KEY` and nowhere
    else — so the mode-600 keyfile `install.sh` writes was never found, and a machine holding a
    perfectly good tier-2 key was told "no chain key available" and refused to render. `cmd_prove`
    fixed exactly this and said so in a comment; `cmd_ops` was fixed next. The page was the half
    still doing it the old way.

    `prefer_keyid` matters here for the same reason it matters there: this attests from the PROOF
    ledger, so the key that ledger was written under beats the best-protected key available.
    Promoting a stronger key mid-chain makes every prior entry fail verification and surface as
    tampering — the one false positive this software must never emit about its own evidence.

    `--keyfile` still wins, exactly as before, and `$STOP_GUESSING_CHAIN_KEY` is still consulted.
    Nothing that worked before stops working; two providers that were invisible become visible.
    """
    got = discover(getattr(args, "keyfile", None),
                   prefer_keyid=keyid_of_ledger(runner.DEFAULT_LEDGER))
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

    # Having A key is not having THE key. Widening `_key` to `discover()` fixed a real defect — the
    # installed keyfile was invisible — but it also introduced this: a key that verifies nothing in
    # the proof ledger now satisfies the `is None` guard above, `attest_self` reads 0 proven because
    # every entry fails its MAC, and the page renders that as fact. Refusing without a key while
    # rendering 0/21 with the wrong one would be a worse bug than the one being fixed, and the same
    # false-tampering family as #90.
    #
    # Reported, not worked around: nothing here re-keys the ledger, because re-keying evidence to
    # make it verify is the alteration this project exists to refuse.
    # `same_key`, not `!=`: the provider is a prefix on the keyid, so supplying the very key this
    # ledger was written under via --keyfile rather than the environment would otherwise be refused
    # as the wrong key. See `keys.key_fingerprint`.
    wrote_under = keyid_of_ledger(runner.DEFAULT_LEDGER)
    if wrote_under and not same_key(key.keyid, wrote_under):
        raise NoChainKey(
            f"the proof ledger was written under {wrote_under}, but the key available here is "
            f"{key.keyid}. Every proof would fail its MAC, the attestation would report 0 proven, "
            "and the page would state that as fact. This is a missing key, not damaged evidence — "
            f"supply {wrote_under} via $STOP_GUESSING_CHAIN_KEY or --keyfile. If it is genuinely "
            "lost, the proofs must be re-run under a new key (docs/REATTESTATION.md); they cannot "
            "be re-keyed in place."
        )
    attest = runner.attest_self(key)
    claims = runner.load_claims()
    caiq_path = repo_root() / "docs" / "ai-caiq" / "stop-guessing.yaml"
    caiq = yaml.safe_load(caiq_path.read_text(encoding="utf-8")) if caiq_path.is_file() else None
    return build(attest, claims, caiq)


def frameworks_html() -> str:
    """The same posture as `frameworks_markdown`, for the published page.

    One source (docs/frameworks.yaml), two renderers. The page and the README cannot disagree about
    what has been benchmarked, which is exactly how the old hand-written Standards table went wrong.
    """
    rows = (_frameworks_doc().get("frameworks") or [])
    if not rows:
        return ""
    counts = {tier: len([r for r in rows if r["tier"] == tier]) for tier in TIER_ORDER}

    out = ['<h2>Standards and benchmarks</h2>',
           '<p><strong>&ldquo;Aligned to&rdquo; is not &ldquo;benchmarked against.&rdquo;</strong> '
           'A framework is listed as validated only where a third party&rsquo;s validator returns a '
           'verdict on this toolchain&rsquo;s output <em>and</em> a control confirms that validator '
           'rejects a deliberately broken input. Everything weaker is labelled as what it is.</p>',
           f'<p class="verdict">{counts["externally-validated"]} externally validated &middot; '
           f'{counts["self-asserted"]} self-asserted &middot; {counts["mapped"]} mapped &middot; '
           f'{counts["design-target"]} design targets &middot; '
           f'{counts["not-benchmarked"]} named but not benchmarked &middot; '
           f'{counts["out-of-scope"]} out of scope</p>']

    for tier in TIER_ORDER:
        group = [r for r in rows if r["tier"] == tier]
        if not group:
            continue
        label, meaning = TIER_LABEL[tier]
        out.append(f'<h3>{_esc(label)}</h3><p class="muted">{_esc(meaning)}.</p>')
        out.append('<table><thead><tr>')
        if tier == "externally-validated":
            out.append('<th>Framework</th><th>Validator</th><th>Result</th><th>Control</th>')
        elif tier in ("not-benchmarked", "out-of-scope"):
            out.append('<th>Framework</th><th>Why it is not here</th>')
        else:
            out.append('<th>Framework</th><th>What is claimed, exactly</th>')
        out.append('</tr></thead><tbody>')
        if tier == "not-benchmarked":
            group = sorted(group, key=lambda x: x.get("priority", 99))
        for r in group:
            name = f'<strong>{_esc(r["name"])}</strong>'
            if tier == "externally-validated":
                out.append(f'<tr><td>{name}</td><td><code>{_esc(r.get("validator",""))}</code></td>'
                           f'<td>{_esc(_one_line(r.get("result")))}</td>'
                           f'<td>{_esc(_one_line(r.get("control")))}</td></tr>')
            elif tier in ("not-benchmarked", "out-of-scope"):
                cell = _one_line(r.get("why") or r.get("what"))
                extra = ""
                if r.get("scope_limit"):
                    extra += f'<br><strong>Scope limit:</strong> {_esc(_one_line(r["scope_limit"]))}'
                if r.get("review"):
                    extra += f'<br><strong>Review when:</strong> {_esc(_one_line(r["review"]))}'
                out.append(f'<tr><td>{name}</td><td>{_esc(cell)}{extra}</td></tr>')
            else:
                detail = _one_line(r.get("result") or r.get("what"))
                if r.get("gap"):
                    detail += f' Gap: {_one_line(r["gap"])}'
                out.append(f'<tr><td>{name}</td><td>{_esc(detail)}</td></tr>')
        out.append('</tbody></table>')
    return "\n".join(out)


def _esc(s) -> str:
    import html as _html

    return _html.escape(str(s or ""))

def replace_frameworks(text: str, block: str) -> str:
    """Swap the generated framework block, or append it if the markers are absent."""
    if FW_BEGIN in text and FW_END in text:
        head = text[:text.index(FW_BEGIN)]
        tail = text[text.index(FW_END) + len(FW_END):]
        return head + block + tail
    return text.rstrip() + "\n\n## Standards and benchmarks\n\n" + block + "\n"


def _render_readme(args) -> str:
    import yaml

    key = _key(args)
    if key is None:
        raise NoChainKey("no chain key; the README status block would misstate the project")
    attest = runner.attest_self(key)
    claims = runner.load_claims()
    cp = repo_root() / "docs" / "ai-caiq" / "stop-guessing.yaml"
    caiq = yaml.safe_load(cp.read_text(encoding="utf-8")) if cp.is_file() else None
    return readme_status(attest, claims, caiq)


def _splice(text: str, block: str) -> str:
    """Replace the delimited block, leaving hand-written prose alone."""
    if BEGIN not in text or END not in text:
        raise ValueError(f"README is missing the {BEGIN} / {END} markers")
    head, _, rest = text.partition(BEGIN)
    _, _, tail = rest.partition(END)
    return head + block + tail


def cmd_build(args) -> int:
    try:
        html_out = _render(args)
        block = _render_readme(args)
    except NoChainKey as exc:
        print(f"REFUSED: {exc}")
        return 2
    PAGE.write_text(html_out, encoding="utf-8")
    print(f"wrote {PAGE.relative_to(repo_root())} ({len(html_out)} bytes)")
    text = _splice(README.read_text(encoding="utf-8"), block)
    # The framework posture, from docs/frameworks.yaml. Generated for the same reason the status
    # block is: the hand-written Standards table drifted into claiming three frameworks were tested
    # when one was a single-clause schema source, one an untested design target, and one had never
    # been exercised. A conformance claim is the last thing this project should maintain by hand.
    text = replace_frameworks(text, frameworks_markdown())
    README.write_text(text, encoding="utf-8")
    print(f"wrote the generated status and framework blocks in {README.name}")
    return 0


def cmd_check(args) -> int:
    """CI gate: the committed page must match what the ledger currently supports."""
    if not PAGE.is_file():
        print("FAIL: docs/index.html is missing")
        return 1
    current = PAGE.read_text(encoding="utf-8")
    try:
        expected = _render(args)
        block = _render_readme(args)
    except NoChainKey as exc:
        print(f"SKIPPED: {exc}")
        return 2

    stale = []
    if current != expected:
        stale.append("docs/index.html")
    readme = README.read_text(encoding="utf-8")
    if block not in readme:
        stale.append("README.md (generated status block)")

    if not stale:
        print("PASS: the page and the README status block match the current attestation")
        return 0
    print(f"FAIL: {', '.join(stale)} disagrees with the current attestation.")
    print("      Run `stop-guessing page build` and commit the result.")
    print("      A claim that outlives the evidence it cites is how overclaiming starts.")
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
