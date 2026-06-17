"""The single query chokepoint a tool executor calls before touching kdb+.

Whatever the harness (Claude Code, a raw-API agent like TorQ-ops, AgentDojo), the
executor calls `QueryGate.safe_q(tool, tool_input, principal)` for any query tool
and runs ONLY the q it returns - or blocks on the exception. Two routes, one gate:

  * a STRUCTURED tool  -> the compiler emits the q from the request (data, not code)
  * a FREE-FORM q tool -> aegis.freeform_q lifts the safe subset and RECOMPILES it
    through the same compiler (allowlist-on-parse). The agent's raw q is never run.

Both routes return bounded, date-filtered, entitlement-injected q from the trusted
compiler. Anything off the allowlists, or free-form q outside the safe subset, is
rejected, fail-closed.

`allow_freeform=False` turns the free-form route OFF entirely (a structured-only
deployment - the safest posture; the agent simply has no way to submit raw q).
"""

from __future__ import annotations

from .freeform_q import compile_freeform
from .query_compiler import QueryCompiler, StructuredQueryRejected

DEFAULT_STRUCTURED_TOOLS = {"run_structured_query", "structured_query"}
DEFAULT_FREEFORM_TOOLS = {"run_query", "run_q", "query"}


class QueryGate:
    def __init__(self, compiler: QueryCompiler, *, structured_tools=None,
                 freeform_tools=None, allow_freeform: bool = True):
        self.compiler = compiler
        self.structured_tools = set(structured_tools) if structured_tools is not None else set(DEFAULT_STRUCTURED_TOOLS)
        self.freeform_tools = set(freeform_tools) if freeform_tools is not None else set(DEFAULT_FREEFORM_TOOLS)
        self.allow_freeform = allow_freeform

    def is_query_tool(self, tool: str) -> bool:
        return tool in self.structured_tools or tool in self.freeform_tools

    def safe_q(self, tool: str, tool_input: dict, principal: str | None = None) -> str:
        """Return the bounded, allowlisted q to execute, or raise
        StructuredQueryRejected / FreeformRejected (both = block, fail-closed)."""
        if not isinstance(tool_input, dict):
            raise StructuredQueryRejected("query tool input must be an object")

        if tool in self.structured_tools:
            request = tool_input.get("request", tool_input)
            return self.compiler.compile(request, principal=principal)

        if tool in self.freeform_tools:
            if not self.allow_freeform:
                raise StructuredQueryRejected(
                    f"free-form q tool '{tool}' is disabled on this surface (structured-only)")
            q = tool_input.get("query") or tool_input.get("q")
            if not isinstance(q, str) or not q.strip():
                raise StructuredQueryRejected("free-form query tool requires a non-empty 'query' string")
            return compile_freeform(q, self.compiler, principal=principal)

        raise StructuredQueryRejected(f"'{tool}' is not a query tool on this surface")
