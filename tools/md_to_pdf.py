"""Lightweight markdown -> PDF renderer (pure reportlab, no native deps).

Handles the subset our docs use: # / ## / ### headings, **bold**, *italic*,
`code`, - bullets, 1. numbered lists, > blockquote callouts, | pipe tables |,
and --- rules. Em/en dashes are normalised to spaced hyphens (house style).

    python tools/md_to_pdf.py docs/Foo.md            # -> docs/Foo.pdf
    python tools/md_to_pdf.py docs/Foo.md out.pdf
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (ListFlowable, ListItem, Paragraph,
                                SimpleDocTemplate, Spacer, Table, TableStyle)

ACCENT = colors.HexColor("#0f4c81")
INK = colors.HexColor("#1a1a2e")
MUTED = colors.HexColor("#5a5a6e")
BOXBG = colors.HexColor("#eef3f8")
QUOTEBG = colors.HexColor("#f3f0fa")
GRID = colors.HexColor("#c9d6e3")
CONTENT_W = 180 * mm


def _styles():
    s = getSampleStyleSheet()
    s.add(ParagraphStyle("Cover", parent=s["Title"], fontSize=18, leading=22, textColor=ACCENT, spaceAfter=3))
    s.add(ParagraphStyle("Sub", parent=s["Normal"], fontSize=8.8, leading=11.5, textColor=MUTED, spaceAfter=6))
    s.add(ParagraphStyle("H2", parent=s["Heading2"], fontSize=12.5, leading=15, textColor=ACCENT, spaceBefore=11, spaceAfter=4))
    s.add(ParagraphStyle("H3", parent=s["Heading3"], fontSize=10.5, leading=13, textColor=INK, spaceBefore=7, spaceAfter=3))
    s.add(ParagraphStyle("Body", parent=s["Normal"], fontSize=9.1, leading=12.4, textColor=INK, spaceAfter=5))
    s.add(ParagraphStyle("Bull", parent=s["Normal"], fontSize=9, leading=12, textColor=INK))
    s.add(ParagraphStyle("Quote", parent=s["Normal"], fontSize=9, leading=12.3, textColor=INK))
    s.add(ParagraphStyle("Cell", parent=s["Normal"], fontSize=8.1, leading=10.2, textColor=INK))
    s.add(ParagraphStyle("CellH", parent=s["Normal"], fontSize=8.1, leading=10.2, textColor=colors.white, fontName="Helvetica-Bold"))
    return s


def inline(t: str) -> str:
    """Markdown inline -> reportlab mini-HTML."""
    t = t.replace("—", " - ").replace("–", "-")
    spans: list[str] = []

    def stash(m):
        spans.append(m.group(1).replace("\\`", "`"))
        return f"\x00{len(spans) - 1}\x00"

    t = re.sub(r"`([^`]+)`", stash, t)
    t = t.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    t = re.sub(r"\*\*([^*]+)\*\*", r"<b>\1</b>", t)
    t = re.sub(r"\*([^*]+)\*", r"<i>\1</i>", t)

    def restore(m):
        c = spans[int(m.group(1))].replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
        return f"<font face='Courier' size=8>{c}</font>"

    return re.sub(r"\x00(\d+)\x00", restore, t)


def _is_row(line: str) -> bool:
    s = line.strip()
    return s.startswith("|") and s.endswith("|") and len(s) > 1


def _cells(line: str) -> list[str]:
    return [c.strip() for c in line.strip().strip("|").split("|")]


def render(md_path: Path, out_path: Path) -> None:
    s = _styles()
    lines = md_path.read_text(encoding="utf-8").splitlines()
    flow = []
    i, n = 0, len(lines)
    seen_title = False

    def para(text, sty):
        flow.append(Paragraph(inline(text), s[sty]))

    while i < n:
        line = lines[i]
        st = line.strip()

        if st == "" or st == "---":
            i += 1
            continue

        if _is_row(line):  # table block
            rows = []
            while i < n and _is_row(lines[i]):
                rows.append(_cells(lines[i]))
                i += 1
            rows = [r for r in rows if not all(set(c) <= set("-: ") for c in r)]  # drop separator
            if not rows:
                continue
            ncol = max(len(r) for r in rows)
            rows = [r + [""] * (ncol - len(r)) for r in rows]
            body = [[Paragraph(inline(c), s["CellH"] if ri == 0 else s["Cell"]) for c in r]
                    for ri, r in enumerate(rows)]
            t = Table(body, colWidths=[CONTENT_W / ncol] * ncol, repeatRows=1)
            t.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), ACCENT),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, BOXBG]),
                ("GRID", (0, 0), (-1, -1), 0.4, GRID),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 4), ("RIGHTPADDING", (0, 0), (-1, -1), 4),
                ("TOPPADDING", (0, 0), (-1, -1), 3), ("BOTTOMPADDING", (0, 0), (-1, -1), 3)]))
            flow += [t, Spacer(1, 2 * mm)]
            continue

        if st.startswith("> "):  # blockquote callout
            buf = []
            while i < n and lines[i].strip().startswith(">"):
                buf.append(lines[i].strip().lstrip(">").strip())
                i += 1
            txt = " ".join(b for b in buf if b)
            inner = Paragraph(inline(txt), s["Quote"])
            ct = Table([[inner]], colWidths=[CONTENT_W])
            ct.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, -1), QUOTEBG),
                ("LINEBEFORE", (0, 0), (0, -1), 2.5, ACCENT),
                ("LEFTPADDING", (0, 0), (-1, -1), 7), ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                ("TOPPADDING", (0, 0), (-1, -1), 4), ("BOTTOMPADDING", (0, 0), (-1, -1), 4)]))
            flow += [ct, Spacer(1, 2 * mm)]
            continue

        if re.match(r"^\s*([-*]) ", line) or re.match(r"^\s*\d+\. ", line):  # list block
            items, numbered = [], bool(re.match(r"^\s*\d+\. ", line))
            while i < n and (re.match(r"^\s*([-*]) ", lines[i]) or re.match(r"^\s*\d+\. ", lines[i])):
                txt = re.sub(r"^\s*([-*]|\d+\.)\s+", "", lines[i])
                items.append(ListItem(Paragraph(inline(txt), s["Bull"]), leftIndent=10))
                i += 1
            flow.append(ListFlowable(items, bulletType="1" if numbered else "bullet", leftIndent=14))
            flow.append(Spacer(1, 1.5 * mm))
            continue

        if st.startswith("### "):
            para(st[4:], "H3"); i += 1; continue
        if st.startswith("## "):
            para(st[3:], "H2"); i += 1; continue
        if st.startswith("# "):
            para(st[2:], "Cover"); seen_title = True; i += 1; continue
        if seen_title and st.startswith("*") and st.endswith("*") and not st.startswith("**"):
            para(st, "Sub"); i += 1; continue

        # plain paragraph: gather consecutive plain lines
        buf = []
        while i < n and lines[i].strip() and not _is_row(lines[i]) \
                and not lines[i].strip().startswith(("#", ">", "- ", "* ")) \
                and not re.match(r"^\s*\d+\. ", lines[i]) and lines[i].strip() != "---":
            buf.append(lines[i].strip())
            i += 1
        para(" ".join(buf), "Body")

    SimpleDocTemplate(str(out_path), pagesize=A4, leftMargin=15 * mm, rightMargin=15 * mm,
                      topMargin=13 * mm, bottomMargin=12 * mm,
                      title=md_path.stem).build(flow)
    print(f"wrote {out_path}  ({out_path.stat().st_size} bytes)")


def main(argv) -> int:
    if not argv:
        print("usage: python tools/md_to_pdf.py <in.md> [out.pdf]", file=sys.stderr)
        return 2
    md = Path(argv[0])
    out = Path(argv[1]) if len(argv) > 1 else md.with_suffix(".pdf")
    render(md, out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
