"""Rebuild 'When AI Gets the Keys: How We Keep Agents in Bounds' - the diagrammed
technical brief - as an editable, regenerable reportlab document.

Prose + bullets (no data tables), plain-language diagram boxes, and the two flow
diagrams (Core Architecture, Query Regeneration) drawn as vector graphics in code,
so the source is self-contained and version-controllable.

    python tools/build_guard_brief_pdf.py [out.pdf]
"""

from __future__ import annotations

import sys
from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (Flowable, ListFlowable, ListItem, PageBreak,
                                Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle)

OUT = Path(sys.argv[1]) if len(sys.argv) > 1 else \
    Path(__file__).resolve().parent.parent / "docs" / "TorQ-Ops-x-Guard-brief.pdf"

INK = colors.HexColor("#1a1a2e")
ACCENT = colors.HexColor("#0f4c81")
MUTED = colors.HexColor("#5a5a6e")
LOAD = colors.HexColor("#b00020")
BOXBG = colors.HexColor("#eef3f8")
GRID = colors.HexColor("#c9d6e3")
CODEBG = colors.HexColor("#f2f5f8")
CONTENT_W = 178 * mm


def styles():
    s = getSampleStyleSheet()
    s.add(ParagraphStyle("Cover", parent=s["Title"], fontSize=21, leading=25, textColor=ACCENT, spaceAfter=4))
    s.add(ParagraphStyle("Sub", parent=s["Normal"], fontSize=10.5, leading=14, textColor=MUTED, spaceAfter=8))
    s.add(ParagraphStyle("H", parent=s["Heading2"], fontSize=14, leading=17, textColor=ACCENT, spaceBefore=12, spaceAfter=4))
    s.add(ParagraphStyle("Lede", parent=s["Normal"], fontSize=10, leading=13, textColor=INK, fontName="Helvetica-Oblique", spaceAfter=5))
    s.add(ParagraphStyle("Body", parent=s["Normal"], fontSize=9.6, leading=13.5, textColor=INK, spaceAfter=6))
    s.add(ParagraphStyle("Bull", parent=s["Normal"], fontSize=9.5, leading=13, textColor=INK))
    s.add(ParagraphStyle("Cap", parent=s["Normal"], fontSize=8.8, leading=11.5, textColor=MUTED, fontName="Helvetica-Oblique", spaceBefore=2, spaceAfter=4))
    s.add(ParagraphStyle("Mono", parent=s["Normal"], fontName="Courier", fontSize=8, leading=10.6, textColor=colors.HexColor("#0b3a5e")))
    s.add(ParagraphStyle("Foot", parent=s["Normal"], fontSize=7.8, leading=10.5, textColor=MUTED))
    return s


# ---------------------------------------------------------------------------
# Diagram flowables  (plain-language box labels)
# ---------------------------------------------------------------------------

def _box(c, x, y, w, h, lines, *, bg=BOXBG, ed=ACCENT, fs=8, edw=1.0, dashed=False, bold0=True):
    c.setLineWidth(edw); c.setStrokeColor(ed)
    if dashed:
        c.setDash(3, 2)
    c.setFillColor(bg); c.roundRect(x, y, w, h, 4, stroke=1, fill=1); c.setDash()
    c.setFillColor(INK)
    n = len(lines)
    ty = y + h / 2 + (n - 1) * (fs + 1.8) / 2 - fs / 2 + 1
    for i, ln in enumerate(lines):
        c.setFont("Helvetica-Bold" if (i == 0 and bold0) else "Helvetica", fs)
        c.drawCentredString(x + w / 2, ty - i * (fs + 1.8), ln)


def _arrow(c, x1, y1, x2, y2, label=None):
    import math
    c.setStrokeColor(MUTED); c.setLineWidth(1); c.line(x1, y1, x2, y2)
    ang = math.atan2(y2 - y1, x2 - x1)
    for da in (math.radians(152), math.radians(-152)):
        c.line(x2, y2, x2 + 6 * math.cos(ang + da), y2 + 6 * math.sin(ang + da))
    if label:
        c.setFont("Helvetica-Oblique", 6.8); c.setFillColor(MUTED)
        c.drawCentredString((x1 + x2) / 2, (y1 + y2) / 2 + 2, label)


class CoreArch(Flowable):
    def __init__(self, width=CONTENT_W, height=122 * mm):
        super().__init__(); self.width = width; self.height = height

    def wrap(self, *a):
        return self.width, self.height

    def draw(self):
        c = self.canv
        W = self.width; H = self.height
        _box(c, 2, 4, W - 4, H - 8, [], bg=colors.HexColor("#fdf0f0"), ed=LOAD, edw=1.2, dashed=True)
        c.setFont("Helvetica-Bold", 7); c.setFillColor(LOAD)
        c.drawString(8, H - 16, "The model only proposes - it holds no handle of its own; the server routes every action through Guard")
        cx = W / 2
        # AI agent
        _box(c, cx - 90, H - 58, 180, 28, ["AI AGENT", "proposes an action"], fs=8.5, bg=colors.white)
        _arrow(c, cx, H - 58, cx, H - 84, "proposes")
        # Guard (decision point)
        _box(c, cx - 105, H - 134, 210, 44,
             ["GUARD", "checks every action against a signed policy", "allow  /  approval  /  block"], fs=8.3,
             bg=colors.HexColor("#e3edf7"), ed=ACCENT, edw=1.4)
        # Audit + watchdog (side observer)
        _box(c, cx + 125, H - 130, 112, 40, ["AUDIT + WATCHDOG", "logs every", "decision; can", "stop the agent"], fs=6.9,
             bg=colors.HexColor("#eaf6ec"), ed=colors.HexColor("#2e7d32"))
        c.setDash(2, 2); c.setStrokeColor(MUTED); c.setLineWidth(1)
        c.line(cx + 105, H - 112, cx + 125, H - 112); c.setDash()
        # three controlled routes
        rw, gap, ry = 116, 12, H - 200
        xs = [cx - 1.5 * rw - gap, cx - rw / 2, cx + 0.5 * rw + gap]
        _arrow(c, cx - 70, H - 134, xs[0] + rw / 2, ry + 48, "query")
        _arrow(c, cx, H - 134, xs[1] + rw / 2, ry + 48, "tool")
        _arrow(c, cx + 70, H - 134, xs[2] + rw / 2, ry + 48, "network")
        _box(c, xs[0], ry, rw, 48, ["DB QUERIES", "rewritten safe", "and bounded"], fs=7.8)
        _box(c, xs[1], ry, rw, 48, ["TOOL CALLS", "checked; risky ones", "need approval"], fs=7.8)
        _box(c, xs[2], ry, rw, 48, ["NETWORK", "allowlisted", "destinations only"], fs=7.8)
        # funnel into the estate
        c.setStrokeColor(MUTED); c.setLineWidth(1)
        c.line(xs[0] + rw / 2, ry, xs[2] + rw / 2, ry)
        _arrow(c, cx, ry, cx, ry - 24)
        _box(c, cx - 105, ry - 66, 210, 40,
             ["kdb+ ESTATE"], fs=8.3,
             bg=colors.white, ed=INK, edw=1.3)


class Pipeline(Flowable):
    def __init__(self, width=CONTENT_W, height=30 * mm):
        super().__init__(); self.width = width; self.height = height

    def wrap(self, *a):
        return self.width, self.height

    def draw(self):
        c = self.canv
        steps = [["agent's", "query"], ["parse to a", "safe structure"], ["discard the", "original text"],
                 ["recompile a", "bounded query"], ["kdb+ runs", "Guard's query"]]
        n = len(steps); gap = 9
        bw = (self.width - (n - 1) * gap) / n
        y = 6; h = self.height - 18
        for i, lines in enumerate(steps):
            x = i * (bw + gap)
            last = i == n - 1
            _box(c, x, y, bw, h, lines, fs=7.6, bold0=False,
                 bg=colors.HexColor("#eaf6ec") if last else BOXBG,
                 ed=colors.HexColor("#2e7d32") if last else ACCENT)
            if i:
                _arrow(c, i * (bw + gap) - gap - 1, y + h / 2, i * (bw + gap) + 1, y + h / 2)


# ---------------------------------------------------------------------------

def main() -> int:
    s = styles()
    doc = SimpleDocTemplate(str(OUT), pagesize=A4, leftMargin=16 * mm, rightMargin=16 * mm,
                            topMargin=14 * mm, bottomMargin=13 * mm, title="TorQ Ops x Guard")
    st = []

    def P(t, sty="Body"):
        return Paragraph(t, s[sty])

    def bullets(items):
        return ListFlowable([ListItem(Paragraph(x, s["Bull"]), leftIndent=10) for x in items],
                            bulletType="bullet", leftIndent=14, spaceBefore=2)

    def code(lines):
        esc = [ln.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace(" ", "&nbsp;") for ln in lines]
        t = Table([[Paragraph("<br/>".join(esc), s["Mono"])]], colWidths=[CONTENT_W])
        t.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), CODEBG), ("BOX", (0, 0), (-1, -1), 0.4, GRID),
                               ("LEFTPADDING", (0, 0), (-1, -1), 6), ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                               ("TOPPADDING", (0, 0), (-1, -1), 5), ("BOTTOMPADDING", (0, 0), (-1, -1), 5)]))
        return t

    # Cover
    st += [P("TorQ Ops x Guard: When the Support Agent Gets the Keys", "Cover"),
           P("How an AI agent gets real, hands-on access to a kdb+ operational stack - and still can't take it "
             "down.", "Sub"),
           P("A support engineer gets a page: some tickers in the consolidated book are showing null prices. There "
             "is no button for &ldquo;find the broken feed&rdquo; - the work is to poke around live state, compare "
             "sources, and follow the trail to the cause. This is the kind of first-line investigation we want to "
             "hand to an AI agent, which means giving it real, hands-on access to the kdb+ estate."),
           P("A fixed menu of tools cannot anticipate every support question, so a useful agent has to be able to "
             "try its own query. But an agent free enough to investigate is also free enough to do damage: on kdb+, "
             "one careless query can take the whole process down, and a wrong or manipulated action can reach "
             "production. Telling it to &ldquo;be careful&rdquo; is not a control."),
           P("This brief is for teams whose support already has some hands-on access to live processes - given a "
             "handle, told to be careful, left to learn as they go. (If your agents have no real access yet, you do "
             "not have this problem.) It is how we keep that access safe: the model can propose, but Guard decides.")]

    # Guard in one sentence
    st += [P("Guard in One Sentence", "H"),
           P("Guard is a deterministic checkpoint between an AI agent and the systems it can touch.", "Lede"),
           P("It works in three plain steps: the agent <b>proposes</b> an action; Guard <b>checks</b> it against a "
             "fixed policy and answers allow, ask-a-human, or block; and only an <b>approved</b> action is actually "
             "run. The agent never reaches the system directly."),
           Spacer(1, 1 * mm),
           code(["decision = guard.check(tool_name, tool_args, principal=user_id)",
                 "if decision.effect == \"block\":",
                 "    return refusal(decision)",
                 "if decision.effect == \"require_approval\":",
                 "    return approval_flow(decision)",
                 "return run_tool(tool_name, tool_args)"]),
           Spacer(1, 1.5 * mm),
           code(["def evaluate(action):",
                 "    if policy_missing_or_invalid:",
                 "        return BLOCK",
                 "    findings  = enabled_rule_packs(action)",
                 "    findings += default_deny_grants(action)",
                 "    verdict   = most_severe(findings)   # block > approval > allow",
                 "    audit.record(action, verdict)",
                 "    supervisor.observe(action, verdict)",
                 "    return verdict"]),
           P("A prompt cannot negotiate with Guard. The same action, plus the same policy, always gives the same "
             "result.", "Cap")]

    # Core architecture
    st += [PageBreak(), P("Core Architecture", "H"),
           P("One decision point, three controlled exits: questions to the database, actions, and anything leaving "
             "the system.", "Lede"),
           CoreArch(),
           P("What each part is:"),
           bullets([
               "<b>AI agent</b> - proposes an action; it has no authority to run anything itself.",
               "<b>Guard</b> - a signed-policy checkpoint that returns allow, approval or block; its decision runs "
               "in code the model never executes.",
               "<b>The three routes</b> - DB queries are rewritten into a bounded, allow-listed query; tool calls "
               "are permission-checked (risky ones need approval); network traffic can only reach allow-listed "
               "destinations.",
               "<b>Audit + watchdog</b> - every decision is logged, and a run of blocked attempts trips a breaker "
               "that halts the agent.",
               "<b>The boundary</b> - the model holds no database handle, shell or socket of its own; it only emits "
               "proposals, and the server runs every one through Guard first.",
           ])]

    # Query regeneration
    st += [PageBreak(), P("Query Regeneration", "H"),
           P("This is the core of Guard, and the part worth slowing down on. For database access Guard "
             "<b>does not run the model's query.</b> It reads what the query is asking for, throws the original "
             "text away, and writes a fresh, bounded query of its own.", "Body"),
           Pipeline(),
           P("The database receives Guard's query, never the model's original text.", "Cap"),
           P("<b>A worked example.</b> Back to that null-price page. Triaging the feed, the agent wants the average "
             "bid for NVDA and how many ticks came back null, and proposes this:"),
           code(["select avg bid, sum null bid by sym from prices_exchange where sym=`NVDA"]),
           P("Guard never sends that string. First it <b>lifts</b> the query into a plain structured request - data, "
             "not code:"),
           code(['{ "table":   "prices_exchange",',
                 '  "by":      ["sym"],',
                 '  "aggs":    [ {"fn": "avg", "col": "bid"},',
                 '               {"fn": "sum", "col": "bid", "of": "null", "as": "nb"} ],',
                 '  "filters": [ {"col": "sym", "op": "=", "value": "NVDA"} ] }']),
           P("The raw text is gone - the backticks, the operators, anything executable. Then Guard <b>recompiles</b> "
             "that request into a brand-new query, stamping on the mandatory date filter and row cap the agent never "
             "wrote. This - and only this - is what kdb+ runs:"),
           code(["1000000 sublist (",
                 "  select avg bid, nb:sum null bid by sym",
                 "  from prices_exchange",
                 "  where date=2026.06.23, sym=`NVDA )"]),
           P("The engineer still gets the number they were after - but the query is now pinned to a single date and "
             "capped, so it cannot scan the whole estate or stall the process behind the live desk.", "Body"),
           P("The whole path is two calls - lift, then compile:"),
           code(["def safe_query(tool_input, principal):",
                 "    request = lift(tool_input[\"query\"])           # parse -> structured request, or reject",
                 "    return compiler.compile(request, principal)   # rebuild a bounded, allow-listed query"]),
           P("Three stages, each closing a class of risk:"),
           bullets([
               "<b>Parse</b> - pull out only the parts a query is allowed to have: table, columns, filters, time "
               "window. (The lift step above.)",
               "<b>Reject</b> - anything that doesn't fit that safe shape has nowhere to go. A delete, a shell call, "
               "a second statement hidden after a semicolon: none of them are in the grammar, so the request stops "
               "here, before any database sees it.",
               "<b>Compile</b> - write a new query from the structure, adding the row cap and date bound, and "
               "honouring the access the caller is already entitled to. kdb+ runs Guard's text, never the model's.",
           ]),
           P("So the dangerous cases never reach kdb+ - they fail at parse, or at compile:"),
           code(['delete from prices_exchange',
                 '   -> rejected at parse: only select / exec / meta can be expressed',
                 '',
                 'select sym from trade where date=...; system "..."',
                 '   -> rejected at parse: a second statement has no place in the structure',
                 '',
                 'select pnl from prices_exchange where date=...',
                 "   -> rejected at compile: column 'pnl' is not on the allow-list"]),
           P("The property that makes this strong: because Guard <b>emits</b> the query rather than approving the "
             "model's, a hijacked or simply mistaken model cannot get a dangerous query through - the dangerous "
             "form was never something Guard knows how to write.", "Body")]

    # Customise
    st += [PageBreak(), P("What You Can Customise", "H"),
           P("Guard is driven by policy, so the same engine adapts to very different agents. You decide:"),
           bullets([
               "<b>Tools</b> - which tools exist at all, which roles can call them, and which need a human to approve.",
               "<b>Data</b> - which tables, columns and rows are reachable, row caps, and mandatory date filters.",
               "<b>Network &amp; process</b> - the platform boundary (allow-listed egress, read-only mounts, resource "
               "limits, no ambient shell or credentials) is the operator's to apply; Guard validates the deployment "
               "descriptor declares it.",
               "<b>Files</b> - which paths can be read or written, and which are off-limits.",
               "<b>Operations</b> - where a human must approve, spending ceilings, and the kill switch.",
               "<b>Audit</b> - how every decision is recorded, including hash-chained and off-host options.",
           ]),
           P("So one engine covers a read-only reporting bot, a coding assistant locked to project files, an ops "
             "agent that needs sign-off for anything destructive, and an analyst limited to certain rows and date "
             "ranges - each just a different policy.")]

    # Why it holds
    st += [P("Why It Holds", "H"),
           bullets([
               "<b>Default deny:</b> if it isn't explicitly allowed, it doesn't happen.",
               "<b>Outside the model's reach:</b> the policy decision runs in code the model never executes - it "
               "only emits a proposal that Guard adjudicates.",
               "<b>No handle of its own:</b> the model holds no database connection, shell or socket; the server "
               "routes every action through Guard, so a careless or hijacked query is rewritten or refused before "
               "anything runs.",
               "<b>Signed policy:</b> the gate verifies the policy's signature against a pinned key before loading; "
               "a modified policy fails closed, so the agent cannot widen its own permissions.",
               "<b>Audit:</b> every decision is appended to a hash-chained log, so tampering is evident.",
               "<b>Watchdog:</b> a run of blocked attempts trips a circuit breaker that halts the agent until an "
               "operator resets it.",
               "<b>Deployment boundary:</b> read-only mounts, resource limits and allow-listed egress are the "
               "operator's platform layer - Guard validates the deployment declares them, the platform enforces them.",
           ])]

    # Conclusion
    st += [P("Conclusion", "H"),
           P("Production AI does not fail safely by default. Once an agent has credentials, tools and network "
             "access, a bad output can become a real action."),
           P("Keeping agents in bounds means changing the execution model: restrict what the agent can reach, "
             "rebuild risky outputs into safe forms, require approval for sensitive steps, and record every "
             "decision. The model can stay flexible; the environment around it must be deterministic."),
           P("The practical shift: don't rely on the AI to know its limits. Build systems where the limits are "
             "enforced before anything runs.")]

    doc.build(st)
    print(f"wrote {OUT}  ({OUT.stat().st_size} bytes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
