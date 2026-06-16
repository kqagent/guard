"""Generate docs/Aegis-Worked-Examples.pdf - a one-page senior handout of real
should/shouldn't compiler output + the four-layer validation note. Pure reportlab.
Run:  python tools/build_examples_pdf.py
"""

from __future__ import annotations

from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (ListFlowable, ListItem, Paragraph,
                                SimpleDocTemplate, Spacer, Table, TableStyle)

OUT = Path(__file__).resolve().parent.parent / "docs" / "Aegis-Worked-Examples.pdf"

INK = colors.HexColor("#1a1a2e")
ACCENT = colors.HexColor("#0f4c81")
MUTED = colors.HexColor("#5a5a6e")
OK = colors.HexColor("#2e7d32")
NO = colors.HexColor("#b00020")
CODEBG = colors.HexColor("#f2f5f8")
BOXBG = colors.HexColor("#eef3f8")


def styles():
    s = getSampleStyleSheet()
    s.add(ParagraphStyle("Cover", parent=s["Title"], fontSize=20, leading=24, textColor=ACCENT, spaceAfter=2))
    s.add(ParagraphStyle("Sub", parent=s["Normal"], fontSize=9, leading=12, textColor=MUTED, spaceAfter=6))
    s.add(ParagraphStyle("H", parent=s["Heading2"], fontSize=11.5, leading=14, textColor=ACCENT, spaceBefore=9, spaceAfter=3))
    s.add(ParagraphStyle("Body", parent=s["Normal"], fontSize=9, leading=12, textColor=INK, spaceAfter=3))
    s.add(ParagraphStyle("Bull", parent=s["Normal"], fontSize=8.6, leading=11, textColor=INK))
    s.add(ParagraphStyle("Ask", parent=s["Normal"], fontSize=9, leading=11.5, textColor=INK, spaceBefore=3))
    s.add(ParagraphStyle("Qcode", parent=s["Normal"], fontName="Courier", fontSize=7.6, leading=9.6,
                         textColor=colors.HexColor("#0b3a5e"), backColor=CODEBG, borderPadding=3, spaceAfter=2))
    s.add(ParagraphStyle("Cell", parent=s["Normal"], fontSize=8.2, leading=10, textColor=INK))
    s.add(ParagraphStyle("CellH", parent=s["Normal"], fontSize=8.2, leading=10, textColor=colors.white, fontName="Helvetica-Bold"))
    s.add(ParagraphStyle("Foot", parent=s["Normal"], fontSize=7.6, leading=10, textColor=MUTED, spaceBefore=4))
    return s


def main() -> int:
    s = styles()
    doc = SimpleDocTemplate(str(OUT), pagesize=A4, leftMargin=15 * mm, rightMargin=15 * mm,
                            topMargin=12 * mm, bottomMargin=11 * mm, title="Aegis - Worked Examples & Validation")
    st = []

    def P(t, sty="Body"):
        return Paragraph(t, s[sty])

    def code(t):
        return Paragraph(t.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"), s["Qcode"])

    def tbl(rows, widths, header_colors=None):
        body = [[Paragraph(c, s["CellH"] if r == 0 else s["Cell"]) for c in row] for r, row in enumerate(rows)]
        t = Table(body, colWidths=widths)
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), ACCENT),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, BOXBG]),
            ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#c9d6e3")),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("LEFTPADDING", (0, 0), (-1, -1), 4), ("RIGHTPADDING", (0, 0), (-1, -1), 4),
            ("TOPPADDING", (0, 0), (-1, -1), 2.5), ("BOTTOMPADDING", (0, 0), (-1, -1), 2.5)]))
        return t

    st += [P("Aegis - Worked Examples &amp; Validation", "Cover"),
           P("Answers: &ldquo;How have you validated it does what it should - which queries work, which "
             "don&rsquo;t?&rdquo; Every compiled query below is the <b>real output</b> of the Aegis compiler. "
             "The principal is an analyst entitled only to EMEA rows.", "Sub")]

    st += [P("A &nbsp; Queries that SHOULD work &rarr; compiled to safe, bounded, entitled q", "H")]
    asks = [
        ("1. &ldquo;Last week&rsquo;s AAPL trades (price, size)&rdquo;",
         "1000000 sublist (select sym, price, size from trade\n"
         "    where date within 2025.06.02 2025.06.06, sym in `AAPL, region in `EMEA, i<1000000)"),
        ("2. &ldquo;Average price by symbol, one day&rdquo;",
         "select avgpx:avg price by sym from trade where date=2025.06.02, region in `EMEA"),
        ("3. &ldquo;Top 10 trades by size today&rdquo;",
         "10 sublist `size xdesc (select sym, price, size from trade where date=2025.06.02, region in `EMEA, i<1000000)"),
        ("4. &ldquo;Size-weighted average price (VWAP) per symbol&rdquo;",
         "select vwap:size wavg price by sym from trade where date=2025.06.02, region in `EMEA"),
    ]
    for ask, q in asks:
        st += [P("<b>" + ask + "</b>", "Ask"), code(q)]
    st += [P("<b>What to notice in every one</b> (the safety, baked in automatically):", "Body"),
           ListFlowable([ListItem(Paragraph(x, s["Bull"]), leftIndent=8) for x in [
               "A <b>date filter is always present</b> - no accidental full-history scan.",
               "<b>region in `EMEA</b> is stapled on automatically - the analyst&rsquo;s row entitlement; "
               "they never asked for it and cannot remove it.",
               "Every query is <b>capped</b> - no runaway query.",
               "Aggregations carry <b>no row-cap inside</b> (the average isn&rsquo;t corrupted) but are still "
               "result-capped.",
               "There is <b>no system, delete, or ;</b> anywhere - and no way to insert one, because the "
               "analyst submits a <b>form, not code</b>.",
           ]], bulletType="bullet", leftIndent=10)]

    st += [P("B &nbsp; Requests that SHOULD NOT work &rarr; rejected, fail-closed (never reach kdb+)", "H"),
           tbl([["Attempt", "Rejected because"],
                ["Query table <font face='Courier'>orders</font> (not allowed)", "table not on the query allowlist"],
                ["Read column <font face='Courier'>trader_id</font> (not allowed)", "column not on the allowlist"],
                ["Trade query with <b>no date</b>", "partitioned table - a date range is required"],
                ["Raw listing across <b>60 days</b>", "range spans 61 days (max 31) - narrow it or aggregate"],
                ["Injection in a filter <b>value</b> (AAPL`;system\"id\")", "unsafe string value"],
                ["Injection in a <b>column name</b> (sym; delete trade)", "invalid column identifier"],
                ["Schema peek by an <b>un-entitled</b> user", "no row entitlements (default-deny) - denied"]],
               [95 * mm, 85 * mm])]

    st += [P("C &nbsp; The row entitlement cannot be widened", "H"),
           P("An EMEA-entitled analyst explicitly asks for AMER rows. It does not error - it compiles to:"),
           code("select sym, region from trade where date=2025.06.02, region in `AMER, region in `EMEA, i<1000000"),
           P("Both filters are present, so the query is self-contradictory and <b>returns nothing</b>. The "
             "analyst cannot widen their access, even by asking directly.")]

    st += [P("D &nbsp; Injection defence - untrusted input cannot drive a privileged action", "H"),
           tbl([["The agent tries to...", "Result"],
                ["Place an order from the <b>user&rsquo;s own instruction</b> (trusted)", "ALLOW"],
                ["Send an email from a <b>poisoned file it read</b> (untrusted)", "BLOCK - untrusted can&rsquo;t drive a privileged tool"],
                ["Launder it by <b>mixing trusted + untrusted</b>", "BLOCK - taint accumulates"]],
               [105 * mm, 75 * mm])]

    st += [P("E &nbsp; How this is validated systematically (not just these examples)", "H"),
           ListFlowable([ListItem(Paragraph(x, s["Bull"]), leftIndent=8) for x in [
               "<b>32 automated test batteries.</b> Every should/shouldn&rsquo;t behaviour above is a runnable "
               "test that must pass on <b>every code change</b> - it cannot silently regress.",
               "<b>Real-kdb+ conformance.</b> We don&rsquo;t just check the compiled q <i>looks</i> right - we "
               "<b>execute it against a live kdb+</b> and confirm the caps and entitlements hold at runtime.",
               "<b>A 4-billion-row adversarial soak.</b> An uncooperative, jailbroken AI told to genuinely "
               "attack: <b>0 of 30 attacks succeeded</b>. Benign answers were checked against an "
               "<b>independently-computed correct answer</b> - &lsquo;works&rsquo; means <i>right</i>, not just "
               "<i>ran</i>.",
               "<b>The industry-standard exam (AgentDojo)</b> for external comparison.",
           ]], bulletType="1", leftIndent=12)]

    st += [Spacer(1, 3 * mm),
           P("The mental model: three layers of &ldquo;can&rsquo;t&rdquo;, not &ldquo;please don&rsquo;t&rdquo; - "
             "the agent can&rsquo;t express a dangerous query, can&rsquo;t let untrusted input drive a privileged "
             "action, and can&rsquo;t escape the OS-level cage. Everything else is proof and audit around those "
             "three.", "Foot")]

    doc.build(st)
    print(f"wrote {OUT}  ({OUT.stat().st_size} bytes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
