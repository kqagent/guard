"""Minimal Markdown -> PDF (stdlib + markdown + fpdf2). Usage: md2pdf.py IN.md OUT.pdf"""

from __future__ import annotations

import sys

import markdown
from fpdf import FPDF

# Map non-latin-1 punctuation to ASCII so fpdf2 core fonts can render it.
# Keys built via chr() to keep this source pure-ASCII.
_REPL = {
    chr(0x2014): "-", chr(0x2013): "-", chr(0x2192): "->", chr(0x21D2): "=>",
    chr(0x2022): "-", chr(0x2248): "~", chr(0x2264): "<=", chr(0x2265): ">=",
    chr(0x201C): '"', chr(0x201D): '"', chr(0x2018): "'", chr(0x2019): "'",
    chr(0x2026): "...", chr(0x00A0): " ",
}


def main() -> int:
    src, out = sys.argv[1], sys.argv[2]
    with open(src, encoding="utf-8") as fh:
        text = fh.read()
    for k, v in _REPL.items():
        text = text.replace(k, v)
    html = markdown.markdown(text, extensions=["extra"])
    html = (html.replace("<strong>", "<b>").replace("</strong>", "</b>")
                .replace("<em>", "<i>").replace("</em>", "</i>"))
    pdf = FPDF(format="A4")
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()
    pdf.set_font("Helvetica", size=11)
    pdf.write_html(html)
    pdf.output(out)
    print("wrote", out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
