"""Generate docs/Aegis-Glossary.pdf - a plain-English decoder of the technology
names in the Aegis setup. Pure reportlab. Run: python tools/build_glossary_pdf.py
"""

from __future__ import annotations

from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (Paragraph, SimpleDocTemplate, Spacer, Table,
                                TableStyle)

OUT = Path(__file__).resolve().parent.parent / "docs" / "Aegis-Glossary.pdf"

INK = colors.HexColor("#1a1a2e")
ACCENT = colors.HexColor("#0f4c81")
MUTED = colors.HexColor("#5a5a6e")
BOXBG = colors.HexColor("#eef3f8")


def styles():
    s = getSampleStyleSheet()
    s.add(ParagraphStyle("Cover", parent=s["Title"], fontSize=20, leading=24, textColor=ACCENT, spaceAfter=2))
    s.add(ParagraphStyle("Sub", parent=s["Normal"], fontSize=8.6, leading=11.5, textColor=MUTED, spaceAfter=6))
    s.add(ParagraphStyle("H", parent=s["Heading2"], fontSize=11, leading=13, textColor=ACCENT, spaceBefore=8, spaceAfter=3))
    s.add(ParagraphStyle("Term", parent=s["Normal"], fontSize=8.4, leading=10.5, textColor=INK, fontName="Helvetica-Bold"))
    s.add(ParagraphStyle("Def", parent=s["Normal"], fontSize=8.4, leading=10.5, textColor=INK))
    s.add(ParagraphStyle("Foot", parent=s["Normal"], fontSize=8, leading=11, textColor=MUTED, spaceBefore=5))
    return s


GROUPS = [
    ("What we're protecting", [
        ("kdb+", "The database itself - a very fast database banks use for huge volumes of market data and trades."),
        ("q", "The language you talk to kdb+ in. Extremely powerful (a full programming language) - which is the whole problem: the same language that asks &lsquo;average price&rsquo; can also delete data or run OS commands."),
        ("HDB", "&lsquo;Historical database&rsquo; - the on-disk pile of past data, split by date."),
    ]),
    ("The gatekeeper (the core gate)", [
        ("PDP (Policy Decision Point)", "Jargon for &lsquo;the gatekeeper&rsquo;: the separate program that says yes/no to every action."),
        ("Query compiler", "Takes the AI&rsquo;s structured <i>form</i> and writes the safe q itself. The &lsquo;AI never writes code&rsquo; piece. <b>(The genuinely novel bit.)</b>"),
        ("Detector packs", "Pattern scanners (secrets, personal data, destructive commands) that act as a backup veto."),
        ("Egress proxy", "&lsquo;Egress&rsquo; = outbound network traffic. A checkpoint all outbound traffic must pass; only approved destinations are allowed and the payload is inspected. Stops data being smuggled out."),
    ]),
    ("The AI-specific defences", [
        ("IFC (Information-Flow Control)", "The &lsquo;trusted vs untrusted&rsquo; tagging that stops prompt injection. Tracks where each piece of data <i>came from</i> and blocks untrusted data from triggering a dangerous action."),
        ("Row-level entitlements", "Per-person row filters - which rows each user may see, stapled onto every query, non-removable."),
        ("RBAC", "&lsquo;Role-Based Access Control&rsquo; - standard &lsquo;permissions by job role.&rsquo; Off-the-shelf concept."),
    ]),
    ("Making the rulebook un-forgeable + keeping records", [
        ("Ed25519", "A standard digital-signature algorithm. Signs the rulebook so the AI can&rsquo;t forge or edit it - like a wax seal only the control function can make and anyone can verify."),
        ("WORM (Write Once Read Many)", "A log you can add to but never edit or delete. The tamper-evident audit trail."),
        ("Hash-chain", "Each log entry carries a fingerprint of the one before it, so quietly altering or deleting an entry breaks the chain and is detectable."),
    ]),
    ("The cage (operating-system confinement - all standard Linux features)", [
        ("Namespaces", "A Linux feature giving the AI its own private view of the machine (its own files, network, process list) so it can&rsquo;t see or touch anything else. The cell walls."),
        ("Landlock", "A Linux security feature that lets a program lock itself to a specific allowed set of files, enforced by the kernel and irreversible. Limits which files the AI can reach."),
        ("seccomp", "A Linux feature that filters which low-level system commands (&lsquo;syscalls&rsquo;) a program may make. We block the dangerous ones (loading kernel code, debugging other processes, mounting disks). Shrinks the attack surface."),
        ("rlimits / no-new-privs", "Resource caps (can&rsquo;t fork-bomb the box) and &lsquo;can never gain more privileges than it started with.&rsquo;"),
    ]),
    ("The watchdog", [
        ("Supervisor / circuit-breaker / kill switch", "Watches the <i>stream</i> of actions and automatically quarantines and shuts the AI down if it starts misbehaving."),
        ("Overseer", "A <i>second</i> AI that reads the logs and writes plain-English incident summaries. <b>Advisory only</b> - it never makes the security decision (you never want one AI guarding another as the real control)."),
    ]),
    ("Proving it's correct (the assurance layer)", [
        ("Z3 / SMT", "A mathematical theorem prover. Used to <i>prove</i> the rule-logic is sound (e.g. &lsquo;an allowed action is always within granted permissions&rsquo;), not just test it."),
        ("Cedar", "Amazon&rsquo;s open-source permissions language + checker. Used as an independent second opinion on our rules."),
        ("AgentDojo", "The industry-standard security exam for AI agents - a large set of attack scenarios researchers score systems against."),
        ("MCP (Model Context Protocol)", "The emerging standard way AI agents plug into external tools. We have per-tool rules for it."),
    ]),
]


def main() -> int:
    s = styles()
    doc = SimpleDocTemplate(str(OUT), pagesize=A4, leftMargin=15 * mm, rightMargin=15 * mm,
                            topMargin=12 * mm, bottomMargin=11 * mm, title="Aegis - Technology Glossary")
    st = [Paragraph("Aegis - Technology Glossary", s["Cover"]),
          Paragraph("A plain-English decoder for the names in the Aegis setup. The reassuring point: almost "
                    "none of this is exotic - Ed25519, namespaces, Landlock, seccomp, Z3, Cedar are standard, "
                    "battle-tested components. We did not invent cryptography or sandboxing. The two original "
                    "pieces are the <b>query compiler</b> (the AI fills a form, we write the safe query) and "
                    "wiring <b>information-flow control</b> onto a kdb+ agent. Everything else is well-understood "
                    "parts assembled into one fail-closed, signed, audited gate.", s["Sub"])]

    for title, rows in GROUPS:
        st.append(Paragraph(title, s["H"]))
        body = [[Paragraph(t, s["Term"]), Paragraph(d, s["Def"])] for t, d in rows]
        tbl = Table(body, colWidths=[44 * mm, 136 * mm])
        tbl.setStyle(TableStyle([
            ("ROWBACKGROUNDS", (0, 0), (-1, -1), [colors.white, BOXBG]),
            ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#c9d6e3")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LEFTPADDING", (0, 0), (-1, -1), 5), ("RIGHTPADDING", (0, 0), (-1, -1), 5),
            ("TOPPADDING", (0, 0), (-1, -1), 3), ("BOTTOMPADDING", (0, 0), (-1, -1), 3)]))
        st.append(tbl)

    st += [Spacer(1, 3 * mm),
           Paragraph("The one line: &ldquo;We didn&rsquo;t invent crypto or sandboxing - those are standard "
                     "parts. The original work is the query compiler and the information-flow defence, assembled "
                     "with the rest into one fail-closed, signed, audited gate around the AI.&rdquo;", s["Foot"])]

    doc.build(st)
    print(f"wrote {OUT}  ({OUT.stat().st_size} bytes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
