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
        self.canv.setFont("Helvetica-Bold", 6.4)
        self.canv.setFillColor(LOAD)
        self.canv.drawString(10, 426, "OS CONFINEMENT (load-bearing): non-root / read-only HDB / no shell / no egress / namespaces+Landlock+seccomp")
        # agent
        self._box(cx, 382, colw, 30, ["LLM Agent - any model (Claude / GPT / Bedrock / local)"], fs=9)
        self._arrow(cx + colw / 2, 382, cx + colw / 2, 360, "tool call: STRUCTURED request (never raw q)")
        # PDP
        self._box(cx, 240, colw, 118, [], bg=colors.HexColor("#e3edf7"), ed=ACCENT, edw=1.4)
        self.canv.setFont("Helvetica-Bold", 8)
        self.canv.setFillColor(ACCENT)
        self.canv.drawCentredString(cx + colw / 2, 342, "Policy Decision Point - out-of-process / signed / FAIL-CLOSED")
        gap = 6
        sw = (colw - 16 - 3 * gap) / 4
        xs = [cx + 8 + i * (sw + gap) for i in range(4)]
        self._box(xs[0], 252, sw, 78, ["Query compiler", "structured", "-> bounded q", "+ row entl."], fs=6.8)
        self._box(xs[1], 252, sw, 78, ["Info-flow ctrl", "untrusted", "can't reach", "a sink"], fs=6.8)
        self._box(xs[2], 252, sw, 78, ["Detector packs", "secrets / PII", "destructive", "prod / MCP"], fs=6.8)
        self._box(xs[3], 252, sw, 78, ["Egress proxy", "host allowlist", "SSRF /", "payload DLP"], fs=6.8)
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
                  "<b>Rows are governed, not just tables.</b> A mandatory, non-removable per-principal "
                  "<b>row filter</b> is ANDed into every compiled query - so an analyst sees only the rows "
                  "their entitlement allows, even through joins/set-ops or when they explicitly ask for "
                  "rows outside their set.",
                  "<b>Provenance decides privilege (the injection defense).</b> Every content item the agent "
                  "sees is labelled trusted or untrusted; <b>untrusted content can never drive a privileged "
                  "action</b> (a trade, an email, a write, an egress). The injection need not be detected - "
                  "it simply cannot reach a trigger. This is information-flow control.",
                  "<b>Confinement is load-bearing; the gate is defense-in-depth.</b> The kdb+ process runs "
                  "non-root, read-only HDB, no shell, no egress, under a <b>seccomp syscall filter</b> - so "
                  "even a gate bypass cannot destroy data, reach the network, or attack the kernel.",
              ])]

    story += [P("3 &nbsp; What it is tested to stop", "H"),
              P("The adversarial corpus - driven by an <i>uncooperative</i> model told to actually "
                "try - covers, on the kdb+ analyst surface:")]
    stops = ["Running OS / shell commands on the kdb+ host",
             "Destroying or corrupting data on disk (HDB partitions, the sym file)",
             "Mutating the live data (delete / insert / update)",
             "Stealing sensitive / client data (positions, P&amp;L, account_no, salary)",
             "Reaching outside its lane (non-allowlisted tables, columns, or <b>rows</b> the principal "
             "is not entitled to)",
             "Exfiltration &amp; remote code (outbound connections, native shared-object load)",
             "Hijacking the process itself (message-handler replacement, exit)",
             "Resource exhaustion / DoS (unbounded scans that degrade the box)",
             "Reading protected files (the policy, password lists, the audit log)",
             "Evasion / injection (obfuscation, dynamic eval, injection via the API&rsquo;s own fields)",
             "<b>Indirect prompt injection</b> - a malicious instruction hidden in a tool result (a file, a "
             "query&rsquo;s free-text field, a web/MCP response) that tries to drive a privileged action; "
             "stopped by information-flow control (untrusted-derived actions can&rsquo;t reach a sink)"]
    story += [Table([[P(f"<b>{i+1}.</b>", "Cell"), P(t, "Cell")] for i, t in enumerate(stops)],
                    colWidths=[9 * mm, 155 * mm],
                    style=TableStyle([("VALIGN", (0, 0), (-1, -1), "TOP"), ("BOTTOMPADDING", (0, 0), (-1, -1), 2)]))]

    story += [PageBreak(), P("4 &nbsp; Architecture", "H"), Diagram(), Spacer(1, 3 * mm)]
    comp = [["Component", "Role", "Property"],
            ["PDP (engine, pdp_service)", "decides every action against the signed policy", "out-of-process, fail-closed"],
            ["Query compiler", "compiles structured requests to bounded q", "injection structurally impossible"],
            ["Row entitlements", "mandatory per-principal row filter, ANDed into every table ref", "non-removable, can't widen, covers joins"],
            ["Information-flow control (ifc)", "untrusted content can't reach a privileged sink", "deterministic injection defense"],
            ["Detector packs", "veto: secrets / PII / destructive / prod / resource / MCP", "deterministic, defense-in-depth"],
            ["Egress proxy", "network egress control", "host allowlist + SSRF + payload DLP"],
            ["Signing + change guard", "Ed25519-signed policy; an edit may only narrow without approval", "integrity; widening needs sign-off"],
            ["Schema-drift linter", "diffs the signed policy vs the live schema", "catches lockout + unbounded-scan drift"],
            ["WORM audit", "tamper-evident record of every decision", "hash-chain + off-host mirror + anchor"],
            ["Supervisor + kill switch", "trips a breaker + kills on behavioural tripwires", "deterministic, load-bearing"],
            ["LLM overseer", "reads the audit, narrates incidents", "advisory only, never gates, out-of-band"],
            ["OS confinement", "the containment boundary", "namespaces + Landlock + seccomp"]]
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
                  "declared in the policy. The validator (<font face=\"Courier\">aegis.policy_lint</font>) "
                  "checks it is well-formed, and <font face=\"Courier\">aegis.policy_schema_diff</font> checks "
                  "it against the <b>live schema</b> so a dropped column (silent lockout) or a new "
                  "partitioned table without a date bound (unbounded scan) is caught before signing.",
                  "<b>Row entitlements.</b> Per-principal row filters (which rows each principal may see - by "
                  "region, book, symbol, desk) are declared in the policy and injected mandatorily into every "
                  "compiled query; a wildcard baseline plus table-specific rules combine fail-safe.",
                  "<b>Rules &amp; threat packs.</b> Each pack (secrets, PII terms, destructive ops, prod "
                  "markers, resource limits, MCP manifests, per-tool argument rules) is enabled and tuned in "
                  "the policy. New deterministic rules ship as packs without touching the gate.",
                  "<b>Information-flow policy.</b> Which tools are privileged sinks (egress, write, order, "
                  "scoped query) and which columns/sources are untrusted (free-text fields, external tool "
                  "results) are declared so the IFC veto knows what untrusted content must not drive.",
                  "<b>Tool surface &amp; principals.</b> Which named tools an agent (or a specific principal) "
                  "may use is a grant list, with RBAC scoping per principal; the free-form/break-glass surface "
                  "is a separate, separately-signed policy.",
                  "<b>Supervisor, kill action &amp; confinement.</b> Behavioural tripwires, the kill action "
                  "(signal / docker kill / kubectl delete / callback), and the hardening profile (read-only "
                  "mounts, dropped caps, egress allowlist, syscall filter, resource limits) are declarative "
                  "and CI-checked against your real manifest.",
              ]),
              P("<b>The change workflow:</b> author from the template, run the validators until clean, sign it "
                "(Ed25519), mount it read-only. Every edit is checked by the <b>policy-change guard</b>: a "
                "change that only narrows the allow-set auto-applies; one that <b>widens</b> it (grants any new "
                "capability) is refused until a human approves, and the exact new grant is named. Changing a "
                "rule = edit, re-validate, re-sign, reload the PDP - <b>no code change, fully audited.</b> A "
                "turnkey authoring kit lets the control function do all of this - and run the real-data "
                "re-soak - themselves.")]

    story += [PageBreak(), P("6 &nbsp; How it works (request lifecycle)", "H"),
              ListFlowable([ListItem(Paragraph(x, s["Bull"]), leftIndent=10) for x in [
                  "The agent emits a tool call - on the analyst surface, a <b>structured query "
                  "request</b> (data, not q text).",
                  "The PDP checks the <b>circuit breaker</b> (is this principal quarantined?), then "
                  "<b>default-deny grants</b> (is the tool / table / column even allowed?).",
                  "The <b>query compiler</b> validates every field against allowlists and emits "
                  "<b>bounded q</b> - a date filter is required on partitioned tables, the result is "
                  "capped, the principal&rsquo;s <b>mandatory row-entitlement filter is ANDed in</b> (covering "
                  "both sides of any join/set-op), and the output is re-checked against a backstop. Any "
                  "off-allowlist field &rarr; reject.",
                  "The <b>information-flow veto</b> checks provenance: if the action&rsquo;s arguments were "
                  "derived from <b>untrusted</b> content and the tool is a <b>privileged sink</b>, it is "
                  "blocked before it runs - regardless of what the injected text said.",
                  "<b>Detector packs</b> and the <b>egress proxy</b> veto anything that passes.",
                  "The decision (allow / block / require-approval) is recorded to the <b>tamper-evident "
                  "audit</b>, mirrored off-host.",
                  "The <b>supervisor</b> watches the decision <i>sequence</i>; behavioural tripwires trip a "
                  "<b>circuit breaker</b> that quarantines the principal and fires a <b>kill switch</b>. The "
                  "<b>LLM overseer</b> narrates the incident out-of-band (advisory; never delays a decision).",
                  "Only an allow reaches the real kdb+ gateway - and even then the agent runs inside "
                  "<b>OS confinement</b> that physically prevents shell, file destruction, egress, and the "
                  "dangerous syscalls.",
              ]], bulletType="1", leftIndent=14)]

    story += [P("7 &nbsp; How we tested it", "H"),
              P("Validated by deterministic, runnable proofs - not assertions."),
              bullets([
                  "<b>Acceptance suite (CI-gated):</b> 34 core batteries on Python 3.10-3.12, a wheel "
                  "fresh-install smoke test, the deployment-hardening gate, and ruff - every push.",
                  "<b>Formal:</b> the default-deny grant algebra proved sound &amp; monotonic by exhaustion "
                  "and by <b>Z3/SMT over unbounded domains</b>; AWS&rsquo;s open-source <b>Cedar Analysis CLI "
                  "(CVC5)</b> independently corroborates the exported policy.",
                  "<b>q-semantics conformance on real kdb+:</b> the compiler&rsquo;s emitted q is run against a "
                  "live instance to prove the bounds hold - the materialisation cap holds, a reducing query "
                  "is not corrupted, the entitlement predicate is effective, and the database is read-only "
                  "afterwards.",
                  "<b>OS confinement on real Linux:</b> the adversarial test and Landlock filesystem test "
                  "(fail-closed), plus the <b>seccomp-bpf</b> syscall deny-list verified at the kernel level "
                  "(a blocked syscall is killed with SIGSYS while benign ones run).",
                  "<b>Production-scale realism soak (headline evidence)</b> on ~<b>4 billion rows</b> "
                  "(4 FSP HDBs, 500M trade + 500M quote each, partitioned, 166 GB): <b>no hints</b> (schema "
                  "discovered via meta); an <b>uncooperative attacker</b> (0 refused) &rarr; <b>0/30 attacks "
                  "succeeded</b>; <b>ground-truth correctness</b> checked against independently-computed q. "
                  "<b>Row entitlements</b> held at scale (an analyst sees only its entitled rows, even through "
                  "joins or when asking for others). The process found &amp; fixed real defects in the primary "
                  "control - exactly what scale + ground-truth checking exist to catch.",
                  "<b>Prompt injection (information-flow control):</b> on the estate, a real indirect-injection "
                  "corpus gave <b>100% block, 0 benign false positives</b>. On the <b>AgentDojo</b> standard "
                  "benchmark (official, Opus) the agent keeps real utility and targeted-attack-success sits at "
                  "or near zero with IFC firing on the canonical injections; the clean with-versus-without "
                  "delta on the egress suites is <b>partially complete</b> (an API-credit stop), documented "
                  "and resumable - corroboration of an already-proven property, not a blocker.",
              ])]

    story += [PageBreak(), P("8 &nbsp; Honest limitations - what Aegis is <i>not</i>", "H"),
              bullets([
                  "It governs the agent&rsquo;s <b>actions</b>. It does not make the model truthful, "
                  "doesn&rsquo;t stop it <i>suggesting</i> something unwise in text, and does not replace "
                  "IAM / DLP / change-control - it composes with them.",
                  "<b>The gate is not the containment.</b> A denylist over a Turing-complete language is "
                  "leaky; the kernel confinement is what actually contains a determined agent.",
                  "A namespace/Landlock/seccomp sandbox is <b>weaker than a microVM</b> against a kernel-level "
                  "attacker (out of scope: a kernel 0-day in an allowed syscall, side channels). The seccomp "
                  "layer blocks the clearly-dangerous syscalls, shrinking the largest part of that gap. For "
                  "adversarial multi-tenant, run the same policy inside a microVM (Firecracker/Kata) - "
                  "documented, not yet deployed.",
                  "<b>The injection defense is structural, but its false-positive cost is surface-specific.</b> "
                  "On the kdb+ analyst surface the false-positive rate is zero (query columns are structured "
                  "trusted data). On a broad tool surface (chat, email, document agents), where benign actions "
                  "routinely derive from untrusted content, the same rule can over-block and must be tuned per "
                  "surface - the AgentDojo runs surface exactly this nuance.",
                  "The reported numbers are on a <b>representative</b> corpus and a <b>synthetic</b> "
                  "(if realistic-scale) schema, plus a partial run of the AgentDojo benchmark. They prove the "
                  "design; they are <b>not</b> a production number. The control function must re-soak on the "
                  "<b>real desk corpus and real data</b> before enforcing - the one gate only they can close.",
                  "The free-form (raw-q) surface is governed by <b>allowlist-on-parse</b>: a hand-written "
                  "query is parsed, only the safe subset is accepted, and it is <b>recompiled through the "
                  "trusted compiler</b> (the agent&rsquo;s raw q is never executed). Far stronger than a "
                  "denylist, though the recognised grammar is a curated subset that grows - exotic q is "
                  "rejected (safe) and routed to break-glass; caps + confinement wrap it regardless.",
                  "<b>Numeric overflow is the model&rsquo;s, not the gate&rsquo;s.</b> q <font face=\"Courier\">"
                  "sum</font> over a 64-bit integer column wraps silently; the compiler bounds which rows are "
                  "read and the result size, but does not widen aggregations. The conformance battery surfaces "
                  "this; the fix is an estate-side schema choice (widen those columns to long).",
              ])]

    story += [P("9 &nbsp; Where this sits versus the frontier", "H"),
              P("A 2026 multi-source review places Aegis as strongly <b>aligned</b> with the deterministic, "
                "out-of-band enforcement direction the field has converged on, and <b>ahead</b> in one place: "
                "no competitor was found compiling agent queries as a safety gate (the closest research uses "
                "an LLM to <i>rewrite</i> queries - the opposite trust model), and none at the q/kdb+ plane. "
                "The information-flow layer brings the prompt-injection defense level with the research "
                "frontier. The honest residual gaps are a microVM substrate for fully-untrusted third-party "
                "code and completing the standard-benchmark delta."),
              P("10 &nbsp; Status &amp; what remains", "H"),
              P("<b>Engineering: complete and validated</b> on the structured kdb+ analyst surface - "
                "bounded-by-construction query plane, mandatory row entitlements, deterministic "
                "prompt-injection defense, kernel confinement (namespaces + Landlock + seccomp), two-tier "
                "oversight + kill switch, signed out-of-process PDP with a policy-change guard, tamper-evident "
                "WORM audit, installable package, CI-gated at 34/34."),
              P("<b>Remaining - the human gates (not code):</b>"),
              bullets([
                  "Control-function <b>real-data re-soak</b> (the authoring kit makes this turnkey).",
                  "A <b>design partner</b> running it in monitor mode on production traffic.",
                  "A <b>third-party security audit</b> before a production estate depends on it.",
                  "Completing the <b>AgentDojo official with-versus-without delta</b> on the egress suites "
                  "(resumable; corroboration, not a blocker).",
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
