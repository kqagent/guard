"""Generate docs/kqagent-Authoring-Guard.pdf - how the authoring-time q guard
(Maze lint via Claude Code PreToolUse hooks) works. Pure reportlab.
Run: python tools/build_kqagent_guard_pdf.py
"""

from __future__ import annotations

from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (ListFlowable, ListItem, Paragraph,
                                SimpleDocTemplate, Spacer)

OUT = Path(__file__).resolve().parent.parent / "docs" / "kqagent-Authoring-Guard.pdf"

INK = colors.HexColor("#1a1a2e")
ACCENT = colors.HexColor("#0f4c81")
MUTED = colors.HexColor("#5a5a6e")
LOAD = colors.HexColor("#b00020")


def styles():
    s = getSampleStyleSheet()
    s.add(ParagraphStyle("Cover", parent=s["Title"], fontSize=19, leading=23, textColor=ACCENT, spaceAfter=2))
    s.add(ParagraphStyle("Sub", parent=s["Normal"], fontSize=8.8, leading=11.5, textColor=MUTED, spaceAfter=6))
    s.add(ParagraphStyle("H", parent=s["Heading2"], fontSize=12, leading=14, textColor=ACCENT, spaceBefore=10, spaceAfter=4))
    s.add(ParagraphStyle("Body", parent=s["Normal"], fontSize=9.2, leading=12.5, textColor=INK, spaceAfter=5))
    s.add(ParagraphStyle("Bull", parent=s["Normal"], fontSize=9, leading=12, textColor=INK))
    s.add(ParagraphStyle("Foot", parent=s["Normal"], fontSize=8.4, leading=11, textColor=MUTED, spaceBefore=5))
    return s


def main() -> int:
    s = styles()
    doc = SimpleDocTemplate(str(OUT), pagesize=A4, leftMargin=17 * mm, rightMargin=17 * mm,
                            topMargin=13 * mm, bottomMargin=12 * mm,
                            title="kqagent - How it guards bad q from being written")
    st = []

    def P(t, sty="Body"):
        return Paragraph(t, s[sty])

    def C(t):  # inline monospace
        return f"<font face='Courier' size=8.5>{t}</font>"

    def bullets(items, bt="bullet"):
        return ListFlowable([ListItem(Paragraph(x, s["Bull"]), leftIndent=10) for x in items],
                            bulletType=bt, leftIndent=14, spaceBefore=2)

    st += [P("kqagent - How it guards bad q from being written", "Cover"),
           P("The authoring-time guard (the Maze lint engine wired into Claude Code hooks). This is a "
             "<b>separate system from Aegis</b>: it governs how the agent WRITES q, not what happens when q "
             "RUNS. The clean separation is stated in the limits below.", "Sub")]

    st += [P("The core mechanism (the bit the demo hides)", "H"),
           P("Claude Code fires <b>PreToolUse hooks</b> before it executes any tool. A hook that exits non-zero "
             "(specifically <b>exit code 2</b>) makes Claude Code <b>refuse the tool call</b> and hand the "
             "hook&rsquo;s message back to the model. For a Write/Edit/MultiEdit on a " + C(".q") + " file, "
             "&lsquo;refuse the tool call&rsquo; means <b>the file is never written to disk.</b> That is the "
             "whole enforcement: it isn&rsquo;t the model choosing to behave - it&rsquo;s the harness declining "
             "to carry out the write, deterministically, and telling the model why so it can fix-and-retry."),
           P("So &lsquo;guards bad code from being written&rsquo; is literal: the bad version never lands on "
             "disk; the model only gets to save a version the gate accepts.")]

    st += [P("What's actually wired (three hooks, three jobs - only two block)", "H"),
           bullets([
               "<b>The Maze lint engine - the hard code block.</b> " + C("checkKdbLint()") + " (the same "
               "function " + C("tools/gate.js") + " wraps for the CLI/demo) runs on the proposed content of "
               "every Write/Edit. If the edit introduces a <b>new block-severity violation</b>, Maze&rsquo;s "
               "PreToolUse hook denies the write. This is the layer that stops " + C("=") + "-on-a-string or a "
               "sym-first partition query from ever being saved. 58 rule detectors (regex + AST) in "
               + C("rules-kdb/") + ", defined in " + C("catalog.json") + ".",
               "<b>" + C("skill_gate_hook.py") + " - the workflow block.</b> A second PreToolUse hook. It exits "
               "2 to block a refine write unless " + C("tools/search.py") + " was called recently (a tier-based "
               "minimum number of searches). It doesn&rsquo;t judge the code - it forces the draft &rarr; search "
               "&rarr; refine discipline so refines are informed by the skill index, not by the model guessing.",
               "<b>" + C("pretooluse_q_gate.py") + " - advisory, does NOT block.</b> It runs the lint to predict "
               "which rules would fire, then injects those rule messages + the top-3 skill snippets into the "
               "model&rsquo;s context as additionalContext, so the model sees the fix before it writes. Its own "
               "docstring is explicit: &lsquo;The hook does NOT block.&rsquo;",
           ], bt="1"),
           P("So: one hook hard-blocks bad code (Maze), one hard-blocks skipping the skill step, one feeds the "
             "fix. The first is the &lsquo;can&rsquo;t write bad q&rsquo; guarantee; the others make the model "
             "fix it well.")]

    st += [P("The baseline / bootstrap detail (important and honest)", "H"),
           P("The gate is a <b>&lsquo;don&rsquo;t make it worse&rsquo; gate, not a &lsquo;this file is now "
             "clean&rsquo; gate</b>:"),
           bullets([
               "The <b>first write to a fresh file is allowed</b> (the draft phase - drafts are ungated by design).",
               "On that first touch it captures all pre-existing violations as a <b>baseline</b>.",
               "Subsequent writes are blocked <b>only if they introduce a new block-severity violation beyond "
               "that baseline</b>. Pre-existing bad code is not retroactively blocked.",
           ])]

    st += [P("The honest limits (what the senior should hear)", "H"),
           bullets([
               "<b>Only inside a hook-enabled Claude Code session.</b> A human editing the file, CI, or any "
               "other tool isn&rsquo;t in the loop. It governs the agent&rsquo;s authoring, not the filesystem.",
               "<b>Static lint, not verification.</b> It catches what the 58 rules know. A mistake no rule "
               "encodes passes silently. It does not run the q.",
               "<b>Scoped to " + C(".q") + "/" + C(".k") + "/" + C(".quke") + ".</b> Writing q under another "
               "extension dodges the matcher - a known evasion surface mitigated only by convention (CLAUDE.md "
               "explicitly forbids it).",
               "<b>Syntactic, so gameable on intent.</b> The " + C("date within (2000.01.01, 2099.12.31)") +
               " catch is the proof: the model satisfied the rule&rsquo;s form (date predicate first) while "
               "defeating its purpose. The gate checks structure, not selectivity or intent.",
               "<b>The skill-gate forces a search, not comprehension.</b> It can verify a " + C("search.py") +
               " call happened; it can&rsquo;t verify the model read or applied it.",
               "<b>Authoring-time only.</b> It makes no runtime or security guarantee - nothing about who may "
               "run the query, on which rows, or whether injected input drives it. <i>That is Aegis&rsquo;s job; "
               "this is the clean separation between the two systems.</i>",
           ])]

    st += [Spacer(1, 3 * mm),
           P("One line: &ldquo;kqagent stops the agent from SAVING bad q (a deterministic Claude Code hook that "
             "refuses the write); Aegis governs what happens when q RUNS (who, which rows, injected input). "
             "Authoring guard versus runtime gate - two systems, one clean boundary.&rdquo;", "Foot")]

    doc.build(st)
    print(f"wrote {OUT}  ({OUT.stat().st_size} bytes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
