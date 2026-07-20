"""
Textual ctree dump of a decompiled function, for headless inspection.

IDA has no built-in textual ctree dump — the SDK offers only `citem_t::print1`
(a one-line C rendering of a single item) and the vds5 sample's GUI graph — so
this module walks the tree with a `ctree_visitor_t` and renders one indented
line per item: the op name plus the details that matter when pattern-matching
(lvar index/name, callee name, selector strings, member offsets, cast types).

Functions return strings (no printing) so both the `ast`/`calls` sections of
`probe_func.py` and the IPC server's `decompile` op can serve them.
"""

__all__ = ["describe_expr", "dump_ast", "dump_calls"]

import ida_hexrays
from ida_hexrays import cexpr_t, cfunc_t, cinsn_t, ctree_visitor_t, lvars_t
from idahelper import memory


def _op_name(op: int) -> str:
    """The symbolic `cot_*` / `cit_*` name of a ctree op constant."""
    prefix = "cot_" if op <= ida_hexrays.cot_last else "cit_"
    return f"{prefix}{ida_hexrays.get_ctype_name(op)}"


def describe_expr(e: cexpr_t, lvars: lvars_t) -> str:  # noqa: C901 - a flat op dispatch
    """
    One-line description of the expression `e`: its op name plus identifying details.

    Args:
        e: The expression to describe.
        lvars: The function's lvars, for resolving `cot_var` names.

    Returns:
        A line like `cot_var idx=3 (v3)` or `cot_call -> '_objc_msgSend$count', argc=1`.
    """
    op = e.op
    name = _op_name(op)
    if op == ida_hexrays.cot_var:
        lname = lvars[e.v.idx].name if e.v.idx < lvars.size() else f"#{e.v.idx}"
        return f"{name} idx={e.v.idx} ({lname})"
    if op == ida_hexrays.cot_num:
        return f"{name} val={e.numval()} (0x{e.numval():x})"
    if op == ida_hexrays.cot_obj:
        return f"{name} ea={e.obj_ea:#x} name={memory.name_from_ea(e.obj_ea)!r}"
    if op == ida_hexrays.cot_str:
        return f"{name} str={e.string!r}"
    if op == ida_hexrays.cot_helper:
        return f"{name} helper={e.helper!r}"
    if op == ida_hexrays.cot_call:
        callee = _callee_name(e)
        argc = e.a.size() if e.a is not None else 0
        return f"{name} -> {callee!r}, argc={argc}"
    if op == ida_hexrays.cot_memptr:
        return f"{name} ->m{e.m}"
    if op == ida_hexrays.cot_memref:
        return f"{name} .m{e.m}"
    if op == ida_hexrays.cot_cast:
        try:
            ty = str(e.type)
        except Exception:
            ty = "?"
        return f"{name} to {ty}"
    return name


def _callee_name(call: cexpr_t) -> str:
    """The callee's name (global or helper), or an `<indirect:...>` marker."""
    x = call.x
    if x.op == ida_hexrays.cot_obj:
        return memory.name_from_ea(x.obj_ea) or f"{x.obj_ea:#x}"
    if x.op == ida_hexrays.cot_helper:
        return x.helper
    return f"<indirect:{_op_name(x.op)}>"


def dump_ast(cfunc: cfunc_t) -> str:
    """
    Dump the whole ctree of `cfunc` as an indented text tree, one item per line.

    Args:
        cfunc: The decompiled function whose ctree to dump.

    Returns:
        The tree as a multi-line string.
    """
    lvars = cfunc.get_lvars()
    lines: list[str] = []

    # IDAPython never fires the `leave_*` callbacks, so nesting depth is read from the
    # `parents` stack (maintained by `CV_PARENTS`) rather than a hand-kept counter.
    class Visitor(ctree_visitor_t):
        def __init__(self) -> None:
            super().__init__(ida_hexrays.CV_PARENTS)

        def visit_insn(self, ins: cinsn_t) -> int:
            lines.append(f"{'  ' * self.parents.size()}insn {_op_name(ins.op)} ea={ins.ea:#x}")
            return 0

        def visit_expr(self, e: cexpr_t) -> int:
            lines.append(f"{'  ' * self.parents.size()}expr {describe_expr(e, lvars)}")
            return 0

    Visitor().apply_to(cfunc.body, None)
    return "\n".join(lines)


def dump_calls(cfunc: cfunc_t) -> str:
    """
    Dump every call expression in `cfunc`: callee plus one described line per argument.

    Args:
        cfunc: The decompiled function whose calls to dump.

    Returns:
        The calls as a multi-line string.
    """
    lvars = cfunc.get_lvars()
    lines: list[str] = []

    class Visitor(ctree_visitor_t):
        def __init__(self) -> None:
            super().__init__(ida_hexrays.CV_FAST)

        def visit_expr(self, e: cexpr_t) -> int:
            if e.op != ida_hexrays.cot_call:
                return 0
            lines.append(f"call @ {e.ea:#x}: {_callee_name(e)}")
            if e.a is not None:
                for i in range(e.a.size()):
                    lines.append(f"  arg{i}: {describe_expr(e.a[i], lvars)}")
            return 0

    Visitor().apply_to(cfunc.body, None)
    return "\n".join(lines)
