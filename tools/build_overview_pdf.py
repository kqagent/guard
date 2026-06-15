"""Generate docs/Aegis-System-Overview.pdf -- an honest technical overview.

Pure reportlab (no native deps), so it builds anywhere. The architecture
diagram is drawn as a vector figure (mirrors the mermaid source in
docs/Aegis-System-Overview.md). Run:  python tools/build_overview_pdf.py
"""

from __future__ import annotations

import math
from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (Flowable, ListFlowable, ListItem, PageBreak,
                                Paragraph, SimpleDocTemplate, Spacer, Table,
                                TableStyle)

OUT = Path(__file__).resolve().parent.parent / "docs" / "Aegis-System-Overview.pdf"

INK = colors.HexColor("#1a1a2e")
ACCENT = colors.HexColor("#0f4c81")
MUTED = colors.HexColor("#5a5a6e")
LOAD = colors.HexColor("#b00020")
BOXBG = colors.HexColor("#eef3f8")
BOXED = colors.HexColor("#0f4c81")
CONFBG = colors.HexColor("#fdf0f0")


def styles():
    s = getSampleStyleSheet()
    s.add(ParagraphStyle("Cover", parent=s["Title"], fontSize=30, leading=34, textColor=ACCENT, spaceAfter=6))
    s.add(ParagraphStyle("Sub", parent=s["Normal"], fontSize=12, leading=16, textColor=MUTED, alignment=TA_CENTER, spaceAfter=4))
    s.add(ParagraphStyle("H", parent=s["Heading2"], fontSize=15, leading=18, textColor=ACCENT, spaceBefore=14, spaceAfter=6))
    s.add(ParagraphStyle("Body", parent=s["Normal"], fontSize=10, leading=14.5, textColor=INK, alignment=TA_LEFT, spaceAfter=6))
    s.add(ParagraphStyle("Bull", parent=s["Normal"], fontSize=10, leading=14, textColor=INK))
    s.add(ParagraphStyle("Cell", parent=s["Normal"], fontSize=8.5, leading=11, textColor=INK))
    s.add(ParagraphStyle("CellH", parent=s["Normal"], fontSize=8.5, leading=11, textColor=colors.white, fontName="Helvetica-Bold"))
    s.add(ParagraphStyle("Foot", parent=s["Normal"], fontSize=8, leading=10, textColor=MUTED, alignment=TA_CENTER))
    return s


class Diagram(Flowable):
    """Vector architecture diagram. ASCII-only text (canvas draws literal chars)."""
    def __init__(self, width=172 * mm, height=156 * mm):
        super().__init__()
        self.width = width
        self.height = height

    def wrap(self, *a):
        return self.width, self.height

    def _box(self, x, y, w, h, lines, *, bg=BOXBG, ed=BOXED, fs=8.5, edw=1.0, dashed=False):
        c = self.canv
        c.setLineWidth(edw)
        c.setStrokeColor(ed)
        if dashed:
            c.setDash(3, 2)
        c.setFillColor(bg)
        c.roundRect(x, y, w, h, 4, stroke=1, fill=1)
        c.setDash()
        c.setFillColor(INK)
        n = len(lines)
        ty = y + h / 2 + (n - 1) * (fs + 1.5) / 2 - fs / 2 + 1
        for i, ln in enumerate(lines):
            c.setFont("Helvetica-Bold" if i == 0 else "Helvetica", fs)
            c.drawCentredString(x + w / 2, ty - i * (fs + 1.5), ln)

    def _arrow(self, x1, y1, x2, y2, label=None, dashed=False):
        c = self.canv
        c.setStrokeColor(MUTED)
        c.setLineWidth(1)
        if dashed:
            c.setDash(2, 2)
        c.line(x1, y1, x2, y2)
        c.setDash()
        ang = math.atan2(y2 - y1, x2 - x1)
        for da in (math.radians(152), math.radians(-152)):
            c.line(x2, y2, x2 + 6 * math.cos(ang + da), y2 + 6 * math.sin(ang + da))
        if label:
            c.setFont("Helvetica-Oblique", 7)
            c.setFillColor(MUTED)
            parts = label.split("\n")
            mx, my = (x1 + x2) / 2, (y1 + y2) / 2
            for i, part in enumerate(parts):
                c.drawCentredString(mx, my + (len(parts) - 1) * 4 - i * 8, part)

    def draw(self):
        W = self.width
        colw = 250
        cx = 12
        # confinement wrapper (load-bearing)
        self._box(4, 150, colw + 18, 272, [], bg=CONFBG, ed=LOAD, edw=1.2, dashed=True)
        self.canv.setFont("Helvetica-Bold", 6.8)
        self.canv.setFillColor(LOAD)
        self.canv.drawString(10, 426, "OS CONFINEMENT (load-bearing): non-root / read-only HDB / no shell / no egress")
        # agent
        self._box(cx, 382, colw, 30, ["LLM Agent - any model (Claude / GPT / Bedrock / local)"], fs=9)
        self._arrow(cx + colw / 2, 382, cx + colw / 2, 360, "tool call: STRUCTURED request (never raw q)")
        # PDP
        self._box(cx, 240, colw, 118, [], bg=colors.HexColor("#e3edf7"), ed=ACCENT, edw=1.4)
        self.canv.setFont("Helvetica-Bold", 8)
        self.canv.setFillColor(ACCENT)
        self.canv.drawCentredString(cx + colw / 2, 342, "Policy Decision Point - out-of-process / signed / FAIL-CLOSED")
        sw = (colw - 32) / 3
        self._box(cx + 8, 252, sw, 78, ["Query Compiler", "structured ->", "bounded,", "allowlisted q"], fs=7.5)
        self._box(cx + 12 + sw, 252, sw, 78, ["Detector packs", "secrets / PII /", "destructive /", "prod / MCP"], fs=7.5)
        self._box(cx + 16 + 2 * sw, 252, sw, 78, ["Egress proxy", "host allowlist /", "SSRF /", "payload DLP"], fs=7.5)
        self._arrow(cx + colw / 2, 240, cx + colw / 2, 218, "only safe, bounded, allowlisted actions")
        # production systems
        self._box(cx, 184, colw, 32, ["Production systems", "kdb+ HDB & gateways / network"], fs=9)
        # control function
        self._box(cx, 120, colw, 24, ["Control function authors + signs the policy (read-only mount)"], fs=7.5,
                  bg=colors.HexColor("#f3f0fa"), ed=colors.HexColor("#5b3fa0"))
        self._arrow(cx + colw / 2, 144, cx + colw / 2, 150, dashed=True)
        # right column
        rx = colw + 42
        rw = W - rx - 6
        self.canv.setFont("Helvetica-Bold", 7.5)
        self.canv.setFillColor(MUTED)
        self.canv.drawString(rx, 426, "OBSERVE & CONTROL")
        self._box(rx, 360, rw, 48, ["Tamper-evident", "WORM audit", "hash-chain / mirror", "/ anchor"], fs=7.5,
                  bg=colors.HexColor("#eaf6ec"), ed=colors.HexColor("#2e7d32"))
        self._box(rx, 300, rw, 48, ["Supervisor +", "circuit-breaker", "KILL SWITCH", "(deterministic)"], fs=7.5,
                  bg=colors.HexColor("#fdeeea"), ed=LOAD)
        self._box(rx, 248, rw, 44, ["LLM overseer", "narrates incidents", "(advisory -", "never gates)"], fs=7.5,
                  bg=colors.HexColor("#eef3f8"), ed=BOXED)
        self._arrow(cx + colw, 326, rx, 384, "every decision", dashed=True)
        self._arrow(rx + rw / 2, 300, rx + rw / 2, 292, "incident", dashed=True)


def main() -> int:
    s = styles()
    doc = SimpleDocTemplate(str(OUT), pagesize=A4, leftMargin=18 * mm, rightMargin=18 * mm,
                            topMargin=16 * mm, bottomMargin=14 * mm, title="Aegis - System Overview")
    story = []

    def P(t, st="Body"):
        return Paragraph(t, s[st])

    def bullets(items, st="Bull"):
        return ListFlowable([ListItem(Paragraph(x, s[st]), leftIndent=10) for x in items],
                            bulletType="bullet", leftIndent=12, spaceBefore=1)

    # cover
    story += [Spacer(1, 42 * mm), P("Aegis", "Cover"),
              P("Guardrails an LLM agent cannot ignore", "Sub"), Spacer(1, 4 * mm),
              P("A deterministic, fail-closed policy gate for deploying LLM agents on "
                "production kdb+/q estates", "Sub"), Spacer(1, 30 * mm),
              P("Honest technical overview - engineering complete on the structured kdb+ "
                "analyst surface; remaining gates are human (real-data re-soak, design partner, "
                "third-party audit).", "Foot"),
              P("Working name. MIT licensed. Not a security guarantee or legal advice.", "Foot"),
              PageBreak()]

    story += [P("1 &nbsp; Problem statement", "H"),
              P("Banks and trading firms want LLM agents working <b>on and around production kdb+ "
                "systems</b> - tickerplants, real-time and historical databases, gateways. The "
                "value is real; so is the danger:"),
              bullets([
                  "q is a full programming language reached through the <b>same channel as a query</b>. "
                  "One string can run shell, delete the HDB, kill the tickerplant (a market-data outage "
                  "- a regulatory event), overwrite the sym file (silently corrupting every symbol "
                  "column), open connections, or exfiltrate client positions and P&amp;L.",
                  "An LLM is non-deterministic and <b>promptable by its own inputs</b> - a "
                  "prompt-injection in a tool result can make a well-aligned model act.",
              ]),
              P("<b>Why the obvious defenses fail.</b> Anything in the model&rsquo;s prompt "
                "(&ldquo;you must not delete data&rdquo;) is <i>advice</i> - attended to "
                "probabilistically and ignored some fraction of the time. Classifier / LLM-judge "
                "guardrails have been empirically evaded up to 100%. The field&rsquo;s conclusion: "
                "<b>never rely on the model for security-critical decisions.</b>")]

    story += [P("2 &nbsp; The core idea", "H"),
              P("A real control is a <b>deterministic checkpoint a separate process decides, before the "
                "action runs.</b> Aegis does not <i>ask</i> the model to behave; it <i>decides</i> "
                "whether each action happens."),
              bullets([
                  "<b>Out-of-model, out-of-process.</b> The decision point runs where the agent "
                  "can&rsquo;t tamper with it; the model&rsquo;s output is an <i>input</i>, never trusted.",
                  "<b>Default-deny - enumerate goodness, not badness.</b> Only granted capabilities "
                  "are allowed; blocking &ldquo;bad&rdquo; patterns on a Turing-complete language is a "
                  "losing arms race.",
                  "<b>Fail-closed.</b> Missing/forged policy, unreachable PDP, unknown tool, any error "
                  "&rarr; block.",
                  "<b>The query plane is bounded by construction.</b> The agent <b>never sends raw q</b> "
                  "- it sends a <i>structured request</i> that Aegis <b>compiles</b> into bounded, "
                  "allowlisted q. Dangerous operations have <b>no slot in the grammar</b>: structurally "
                  "impossible, not merely detected.",
                  "<b>Confinement is load-bearing; the gate is defense-in-depth.</b> The kdb+ process runs "
                  "non-root, read-only HDB, no shell, no egress - so even a gate bypass cannot "
                  "destroy data or reach the network.",
              ])]

    story += [P("3 &nbsp; What it is tested to stop", "H"),
              P("The adversarial corpus - driven by an <i>uncooperative</i> model told to actually "
                "try - covers, on the kdb+ analyst surface:")]
    stops = ["Running OS / shell commands on the kdb+ host",
             "Destroying or corrupting data on disk (HDB partitions, the sym file)",
             "Mutating the live data (delete / insert / update)",
             "Stealing sensitive / client data (positions, P&amp;L, account_no, salary)",
             "Reaching outside its lane (non-allowlisted tables, the production HDB)",
             "Exfiltration &amp; remote code (outbound connections, native shared-object load)",
             "Hijacking the process itself (message-handler replacement, exit)",
             "Resource exhaustion / DoS (unbounded scans that degrade the box)",
             "Reading protected files (the policy, password lists, the audit log)",
             "Evasion / injection (obfuscation, dynamic eval, injection via the API&rsquo;s own fields)"]
    story += [Table([[P(f"<b>{i+1}.</b>", "Cell"), P(t, "Cell")] for i, t in enumerate(stops)],
                    colWidths=[9 * mm, 155 * mm],
                    style=TableStyle([("VALIGN", (0, 0), (-1, -1), "TOP"), ("BOTTOMPADDING", (0, 0), (-1, -1), 2)]))]

    story += [PageBreak(), P("4 &nbsp; Architecture", "H"), Diagram(), Spacer(1, 3 * mm)]
    comp = [["Component", "Role", "Property"],
            ["PDP (engine, pdp_service)", "decides every action against the signed policy", "out-of-process, fail-closed"],
            ["Query compiler", "compiles structured requests to bounded q", "injection structurally impossible"],
            ["Detector packs", "veto: secrets / PII / destructive / prod / resource / MCP", "deterministic, defense-in-depth"],
            ["Egress proxy", "network egress control", "host allowlist + SSRF + payload DLP"],
            ["Signing", "Ed25519-signed policy; agent cannot forge", "integrity / non-repudiation"],
            ["WORM audit", "tamper-evident record of every decision", "hash-chain + off-host mirror + anchor"],
            ["Supervisor + kill switch", "trips a breaker + kills on behavioural tripwires", "deterministic, load-bearing"],
            ["LLM overseer", "reads the audit, narrates incidents", "advisory only, never gates, out-of-band"],
            ["OS confinement", "the containment boundary", "kernel-enforced (Landlock + namespaces)"]]
    t = Table([[Paragraph(c, s["CellH"] if r == 0 else s["Cell"]) for c in row] for r, row in enumerate(comp)],
              colWidths=[42 * mm, 74 * mm, 48 * mm])
    t.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), ACCENT),
                           ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, BOXBG]),
                           ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#c9d6e3")),
                           ("VALIGN", (0, 0), (-1, -1), "MIDDLE"), ("LEFTPADDING", (0, 0), (-1, -1), 5),
                           ("TOPPADDING", (0, 0), (-1, -1), 3), ("BOTTOMPADDING", (0, 0), (-1, -1), 3)]))
    story += [t]

    story += [PageBreak(), P("5 &nbsp; Customising it to your estate", "H"),
              P("The policy is <b>data</b>, owned by the control function - not code. Adapting Aegis to a "
                "specific desk or system is editing a signed JSON policy and running a validator: "
                "<b>no engineering, no rebuild of the engine.</b>"),
              bullets([
                  "<b>Schema, tables &amp; columns.</b> The structured-query allowlist - allowed tables, "
                  "per-table columns, required-date tables, row caps, permitted aggregations/operators - is "
                  "declared in the policy. Add a table or column the desk needs, or remove one that is "
                  "off-limits, by editing the allowlist; the validator (<font face=\"Courier\">aegis."
                  "policy_lint</font>) checks it is well-formed before signing.",
                  "<b>Rules &amp; threat packs.</b> Each pack (secrets, PII terms, destructive ops, prod "
                  "markers, resource limits, MCP manifests, per-tool argument rules) is enabled and tuned in "
                  "the policy - turn a pack on or off, add a sensitive term, a prod host/port pattern, a "
                  "protected path. New deterministic rules ship as packs without touching the gate.",
                  "<b>Tool surface &amp; principals.</b> Which named tools an agent (or a specific principal) "
                  "may use is a grant list, with RBAC scoping per principal; the free-form/break-glass surface "
                  "is a separate, separately-signed policy.",
                  "<b>Supervisor &amp; kill action.</b> Behavioural tripwires (which rules are critical, the "
                  "block/escalation thresholds) and the kill action (signal / docker kill / kubectl delete / "
                  "callback) are policy-configured.",
                  "<b>Confinement &amp; deployment.</b> The hardening profile (read-only mounts, dropped caps, "
                  "egress allowlist, resource limits) is declarative and CI-checked against your real manifest.",
              ]),
              P("<b>The change workflow:</b> author from the template, run the validator until clean, sign it "
                "(Ed25519), mount it read-only. Changing a rule = edit, re-validate, re-sign, reload the PDP - "
                "<b>no code change, fully audited.</b> A turnkey authoring kit "
                "(<font face=\"Courier\">policy.kdb.template.json</font> + the validator + a guide) lets the "
                "control function do all of this - and run the real-data re-soak - themselves.")]

    story += [PageBreak(), P("6 &nbsp; How it works (request lifecycle)", "H"),
              ListFlowable([ListItem(Paragraph(x, s["Bull"]), leftIndent=10) for x in [
                  "The agent emits a tool call - on the analyst surface, a <b>structured query "
                  "request</b> (data, not q text).",
                  "The PDP checks the <b>circuit breaker</b> (is this principal quarantined?), then "
                  "<b>default-deny grants</b> (is the tool / table / column even allowed?).",
                  "The <b>query compiler</b> validates every field against allowlists and emits "
                  "<b>bounded q</b> - a date filter is required on partitioned tables, the result is "
                  "capped, and the compiled output is re-checked against a dangerous-construct backstop. "
                  "Any off-allowlist field &rarr; reject.",
                  "<b>Detector packs</b> and the <b>egress proxy</b> veto anything that passes.",
                  "The decision (allow / block / require-approval) is recorded to the <b>tamper-evident "
                  "audit</b>, mirrored off-host.",
                  "The <b>supervisor</b> watches the decision <i>sequence</i>; behavioural tripwires trip a "
                  "<b>circuit breaker</b> that quarantines the principal and fires a <b>kill switch</b>. The "
                  "<b>LLM overseer</b> narrates the incident out-of-band (advisory; never delays a decision).",
                  "Only an allow reaches the real kdb+ gateway - and even then the agent runs inside "
                  "<b>OS confinement</b> that physically prevents shell, file destruction, and egress.",
              ]], bulletType="1", leftIndent=14)]

    story += [P("7 &nbsp; How we tested it", "H"),
              P("Validated by deterministic, runnable proofs - not assertions."),
              bullets([
                  "<b>Acceptance suite (CI-gated):</b> 27 core batteries on Python 3.10-3.12, a wheel "
                  "fresh-install smoke test, the deployment-hardening gate, and ruff - every push.",
                  "<b>Formal:</b> the default-deny grant algebra proved sound &amp; monotonic by exhaustion "
                  "and by <b>Z3/SMT over unbounded domains</b> (24 theorems).",
                  "<b>OS confinement on real Linux:</b> adversarial test 7/7 + Landlock filesystem test 6/6 "
                  "- kernel-enforced, fail-closed.",
                  "<b>Production-scale realism soak (headline evidence)</b> on ~<b>4 billion rows</b> "
                  "(4 FSP HDBs, 500M trade + 500M quote each, partitioned, 166 GB): <b>no hints</b> (schema "
                  "discovered via meta); an <b>uncooperative attacker</b> (0 refused) &rarr; <b>0/30 attacks "
                  "succeeded</b>; <b>ground-truth correctness</b> checked against independently-computed q "
                  "(served-<i>and-correct</i>). Every benign miss was the model writing the wrong query, "
                  "never the guardrail.",
                  "<b>The process found &amp; fixed two real defects</b> in the primary control (a row cap "
                  "that corrupted aggregations at scale; a follow-on materialization regression) - "
                  "exactly what scale + ground-truth checking exist to catch.",
              ])]

    story += [PageBreak(), P("8 &nbsp; Honest limitations - what Aegis is <i>not</i>", "H"),
              bullets([
                  "It governs the agent&rsquo;s <b>actions</b>. It does not make the model truthful, "
                  "doesn&rsquo;t stop it <i>suggesting</i> something unwise in text, and does not replace "
                  "IAM / DLP / change-control - it composes with them.",
                  "<b>The gate is not the containment.</b> A denylist over a Turing-complete language is "
                  "leaky; the kernel confinement is what actually contains a determined agent.",
                  "A namespace/Landlock sandbox is <b>weaker than a microVM</b> against a kernel-level "
                  "attacker. For adversarial multi-tenant, run the same policy inside a microVM "
                  "(Firecracker/Kata) - documented, not yet deployed.",
                  "The reported numbers are on a <b>representative</b> corpus and a <b>synthetic</b> "
                  "(if realistic-scale) schema. They prove the design; they are <b>not</b> a production "
                  "number. The control function must re-soak on the <b>real desk corpus and real data</b> "
                  "before enforcing - the one gate only they can close.",
                  "The free-form (raw-q) surface exists only as <b>admin-only break-glass</b>, separately "
                  "signed, never granted to an analyst; it is honestly weaker than the structured surface.",
              ])]

    story += [P("9 &nbsp; Status &amp; what remains", "H"),
              P("<b>Engineering: complete and validated</b> on the structured kdb+ analyst surface - "
                "bounded-by-construction query plane, kernel confinement, two-tier oversight + kill switch, "
                "signed out-of-process PDP, tamper-evident WORM audit, installable package, CI-gated at 27/27."),
              P("<b>Remaining - the human gates (not code):</b>"),
              bullets([
                  "Control-function <b>real-data re-soak</b> (the authoring kit makes this turnkey).",
                  "A <b>design partner</b> running it in monitor mode on production traffic.",
                  "A <b>third-party security audit</b> before a production estate depends on it.",
              ]),
              P("<b>Recommendation:</b> GO to enforce on the structured analyst surface, conditioned on "
                "confinement deployed (load-bearing), free-form kept off the analyst grant, and the signed "
                "PDP + WORM audit live."),
              Spacer(1, 6 * mm),
              P("This document is an honest overview, not a security guarantee or legal advice. "
                "Generated from tools/build_overview_pdf.py.", "Foot")]

    doc.build(story)
    print(f"wrote {OUT}  ({OUT.stat().st_size} bytes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
