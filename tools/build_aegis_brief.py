"""Render the executive brief as a structured, black-and-white themed PDF.

Pure greyscale, deliberate hierarchy, tight vertical rhythm (no orphaned blocks
or large white gaps - paragraphs/lists flow and break per-line). Unbranded:
no product name, no confidentiality footer.

Usage: python tools/build_aegis_brief.py OUT.pdf
"""

from __future__ import annotations

import sys

from fpdf import FPDF
from fpdf.enums import XPos, YPos

MARGIN = 18.0
INK = 30
DK = 0
BAR = 234
TITLE = "Stopping LLM Agents from Damaging Production Systems"
DATE = "Executive briefing  -  5 June 2026"

# Block kinds: h2, h3, p, ul, examples, gap.
CONTENT = [
    ("p", "This system prevents an LLM agent from taking an action that harms a production "
          "system. It sits between the model and the things it can touch - the shell, the "
          "network, and the kdb+ data store - and makes a deterministic allow / block / "
          "human-approval decision on every action, before the action runs. The model "
          "cannot talk its way past it."),

    ("h2", "1.  The problem: an LLM with tools can break production"),
    ("p", "Give an LLM agent the ability to run commands and query data, and a single "
          "wrong tool call can:"),
    ("ul", [
        "drop or delete a kdb+ table, or run an unbounded query that pulls an entire HDB "
        "into memory and stalls the tickerplant during market hours;",
        "exfiltrate client positions, P&L, or other classified data to an outside host;",
        "delete files, force-push, or touch a production system it was never meant to reach.",
    ]),
    ("p", "Prompt injection makes it worse: instructions hidden in data the agent reads "
          "can hijack the model into issuing exactly such a call. Telling the model 'do not "
          "do that' is advice it can ignore. The control must live outside the model and "
          "decide before the action executes."),

    ("h2", "2.  How it stops them - two enforcement points the LLM cannot bypass"),

    ("h3", "A.  The tool-use gate  (the enforcement engine)"),
    ("p", "Every time the LLM goes to use a tool - run a command, write a file, call an MCP "
          "tool, execute a query - a hook fires and the engine decides allow / block / "
          "require-human-approval before the action executes. The engine, not the model, "
          "decides whether the action happens."),
    ("ul", [
        "In Claude Code, it runs as a PreToolUse hook on every tool call.",
        "Via any model API (Anthropic, OpenAI, Bedrock), a broker intercepts each tool the "
        "model requests before the application executes it.",
        "In production, the engine runs as an out-of-process service the agent cannot tamper "
        "with; if it is unreachable, every action is denied (fail-closed).",
    ]),
    ("p", "The engine is default-deny: the agent can do only what the security team "
          "explicitly granted - specific tools, commands, writable paths, network "
          "destinations, and queryable tables. The policy is a signed file owned by the "
          "control function; because it is cryptographically signed and mounted read-only, "
          "the agent cannot edit or forge its own guardrails. Each MCP server is "
          "zero-privilege until a manifest explicitly grants it tools."),

    ("h3", "B.  The kdb+ proxy  (interface between the agent / MCP and the kdb+ system)"),
    ("p", "The agent never gets a direct handle to kdb+. Its queries pass through the query "
          "proxy, which sits between the MCP / agent layer and the kdb+ data store and "
          "enforces on the real query text:"),
    ("ul", [
        "it parses the q / SQL;",
        "it injects a date-partition filter and a row cap, so a full-table scan cannot pull "
        "an entire HDB into memory and stall the tickerplant;",
        "it blocks mutations (delete / drop / update) - the interface is read-only by default;",
        "it rejects non-allowlisted tables and anything it cannot safely parse (fail-closed).",
    ]),
    ("p", "So the kdb+ production system only ever receives a bounded, read-only, "
          "allowlisted query - a runaway or destructive query physically cannot reach it. A "
          "matching egress proxy sits between the agent and the network and blocks "
          "exfiltration of classified data even to an otherwise-allowlisted host."),

    ("h3", "What actually gets stopped"),
    ("examples", [
        "**BLOCKED**  -  delete from trade / drop table: mutation; the interface is read-only.",
        "**REWRITTEN**  -  unbounded select from quote: date filter + row cap injected before "
        "kdb+ runs it.",
        "**BLOCKED**  -  upload positions data to an external host: network egress + "
        "classified data.",
        "**BLOCKED**  -  query aimed at the production tickerplant: production target.",
        "**BLOCKED**  -  agent edits its own policy or a protected file: signed, read-only "
        "guardrails.",
    ]),
    ("p", "Every decision is written to a tamper-proof audit log - hash-chained, mirrored "
          "off-host, and anchored so deletion or truncation is detectable. This is the "
          "regulator-facing record of what the agent tried and what was allowed."),

    ("h2", "3.  Why it cannot be ignored"),
    ("ul", [
        "The decision is outside the model's control loop - made by a separate process "
        "before the tool runs.",
        "Default-deny - the agent can only do what was explicitly granted.",
        "Fail-closed everywhere - missing or forged policy, unreachable engine, unknown tool, "
        "or any internal error results in BLOCK, never a silent allow.",
        "Signed policy - the agent cannot disable or rewrite its own guardrails.",
        "Proven, not asserted - 15 of 15 automated checks pass from one command; the core "
        "property is established by an exhaustive formal proof; demonstrated gating a real "
        "model call live.",
    ]),

    ("h2", "4.  How this compares to the industry"),
    ("p", "The field has independently converged on this approach - deterministic, "
          "out-of-process, default-deny enforcement that does not trust the model. "
          "Classifier-style content guardrails have been shown evadable up to 100% "
          "(arXiv:2504.11168); standards bodies (CoSAI / OASIS, OWASP) now state plainly: "
          "never rely on the LLM for security-critical validation."),
    ("p", "Production controls split into three planes, and no single competitor spans all "
          "of them: content filtering (e.g. AWS Bedrock Guardrails), tool-call authorization "
          "(e.g. AWS Cedar / AgentCore), and the data / query plane (e.g. Satori, Immuta, "
          "which rewrite SQL to inject row filters). This system unifies the tool-use gate, "
          "the query plane, network egress, signed audit, and confinement into one "
          "default-deny pipeline - and does the query-plane interface for kdb+ / q, which "
          "the SQL-oriented data-governance proxies do not support."),

    ("h2", "5.  Compliance posture  (primary-source verified)"),
    ("ul", [
        "EU AI Act (binding for high-risk systems) maps directly: Art. 12 event logging -> "
        "the tamper-proof audit; Art. 14 human oversight -> the require-approval path; "
        "Art. 15 robustness / cybersecurity -> the red-team-tested, signed, fail-closed gate.",
        "SR 26-2 (Apr 2026) supersedes SR 11-7 and places generative / agentic AI outside "
        "formal model-risk-management scope - so this is the operational governance control "
        "such tools still require, not MRM compliance.",
    ]),

    ("h2", "6.  Status and honest limitations"),
    ("ul", [
        "Implemented and tested today: the tool-use gate, the kdb+ query proxy, the egress "
        "proxy, MCP manifests, signed policy, tamper-proof audit, confinement validation, "
        "formal proof, and the assurance suite - 15/15 core checks green.",
        "It governs agent ACTIONS. It does not make the model truthful and does not replace "
        "the bank's identity, data-loss-prevention, or change-control systems.",
        "Guarantee by surface: containerised operational agents get the strongest posture; "
        "developer laptops get strong defense-in-depth (a laptop cannot be fully sandboxed).",
        "Planned: an official end-to-end adversarial benchmark run, a machine-checked formal "
        "proof, and production audit-sink and human-approval back-ends.",
    ]),

    ("gap", 1.5),
    ("p", "Prepared from two adversarially-verified research passes plus primary-source "
          "verification. Not legal advice; validate regulatory mappings with your control "
          "function."),
]


class Brief(FPDF):
    def header(self):
        if self.page_no() == 1:
            return
        self.set_y(8)
        self.set_text_color(120)
        self.set_font("Helvetica", "", 8)
        self.cell(0, 5, TITLE, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.set_draw_color(180)
        self.set_line_width(0.2)
        self.line(MARGIN, 13.5, self.w - MARGIN, 13.5)
        self.set_y(18)

    def footer(self):
        self.set_y(-13)
        self.set_draw_color(180)
        self.set_line_width(0.2)
        self.line(MARGIN, self.get_y(), self.w - MARGIN, self.get_y())
        self.set_y(-10.5)
        self.set_text_color(120)
        self.set_font("Helvetica", "", 8)
        self.cell(0, 5, f"{self.page_no()}", align="R")


def _bullets(pdf: FPDF, epw: float, items: list, markdown: bool) -> None:
    """Page-break-safe bullets: one multi_cell per item (a hanging dash via a
    raised left margin) so a break never strands a row on an empty page."""
    pdf.set_text_color(INK)
    pdf.set_font("Helvetica", "", 10.3)
    for item in items:
        pdf.set_left_margin(MARGIN + 6)
        pdf.set_x(MARGIN + 2)
        pdf.multi_cell(epw - 2, 4.8, "-  " + item, markdown=markdown,
                       new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.set_left_margin(MARGIN)
        pdf.ln(0.6)
    pdf.ln(0.4)


def render(out: str) -> None:
    pdf = Brief(format="A4")
    pdf.set_auto_page_break(auto=True, margin=16)
    pdf.set_margins(MARGIN, 16, MARGIN)
    pdf.add_page()
    epw = pdf.epw

    # --- title banner (black, no product name) ---
    pdf.set_fill_color(0)
    pdf.rect(MARGIN, 14, epw, 30, style="F")
    pdf.set_xy(MARGIN + 6, 19)
    pdf.set_text_color(255)
    pdf.set_font("Helvetica", "B", 17)
    pdf.multi_cell(epw - 12, 8, TITLE, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.set_xy(MARGIN + 6, 37)
    pdf.set_font("Helvetica", "", 9.5)
    pdf.set_text_color(205)
    pdf.cell(epw - 12, 5, DATE)
    pdf.set_y(50)

    for block in CONTENT:
        kind = block[0]
        if kind == "gap":
            pdf.ln(block[1])
        elif kind == "h2":
            pdf.ln(2)
            pdf.set_text_color(DK)
            pdf.set_font("Helvetica", "B", 12.5)
            pdf.multi_cell(epw, 6.4, block[1], new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            y = pdf.get_y() + 0.4
            pdf.set_draw_color(0)
            pdf.set_line_width(0.5)
            pdf.line(MARGIN, y, MARGIN + epw, y)
            pdf.ln(1.8)
        elif kind == "h3":
            pdf.ln(1)
            pdf.set_fill_color(BAR)
            pdf.set_text_color(DK)
            pdf.set_font("Helvetica", "B", 10.8)
            pdf.multi_cell(epw, 6.0, "  " + block[1], fill=True,
                           new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            pdf.ln(1)
        elif kind == "p":
            pdf.set_text_color(INK)
            pdf.set_font("Helvetica", "", 10.3)
            pdf.multi_cell(epw, 4.8, block[1], new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            pdf.ln(0.8)
        elif kind == "ul":
            _bullets(pdf, epw, block[1], markdown=False)
        elif kind == "examples":
            y = pdf.get_y()
            pdf.set_draw_color(0)
            pdf.set_line_width(0.3)
            pdf.line(MARGIN, y, MARGIN + epw, y)
            pdf.ln(1.5)
            _bullets(pdf, epw, block[1], markdown=True)
            y = pdf.get_y() + 0.2
            pdf.line(MARGIN, y, MARGIN + epw, y)
            pdf.ln(1.2)

    with open(out, "wb") as fh:
        fh.write(bytes(pdf.output()))


if __name__ == "__main__":
    out = sys.argv[1] if len(sys.argv) > 1 else "Aegis-Executive-Summary.pdf"
    render(out)
    print("wrote", out)
