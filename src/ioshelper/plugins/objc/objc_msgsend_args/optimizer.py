__all__ = ["objc_msgsend_argcount_optimizer_t"]

import ida_hexrays
from ida_hexrays import mblock_t, mcallinfo_t, minsn_t, minsn_visitor_t
from idahelper.microcode import minsn, mop

from ioshelper.base.utils import CounterMixin

# objc_msgSend-family dispatch helpers whose prototype is `id f(id, SEL, ...)`.
# By `MMAT_CALLS` IDA has already collapsed the selector stubs (`_objc_msgSend$sel`)
# into one of these helpers, with the selector materialized as `args[1]`.
MSGSEND_HELPERS = frozenset({"objc_msgSend", "objc_msgSendSuper", "objc_msgSendSuper2"})

# The receiver and selector that always precede the per-colon message arguments;
# `mcallinfo.solid_args` is this for every objc_msgSend call.
_FIXED_ARGS = 2

# Genuinely variadic selectors keep gathering message arguments past their last
# colon — the colon count is only their *fixed* parameter count — so their
# argument list must never be truncated. The common Foundation offenders are the
# printf-style `…Format:` methods and the nil-terminated `…Objects:` builders.
_VARIADIC_SELECTORS = frozenset({
    "arrayWithObjects:",
    "initWithObjects:",
    "setWithObjects:",
    "orderedSetWithObjects:",
    "dictionaryWithObjectsAndKeys:",
    "initWithObjectsAndKeys:",
    "raise:format:",
})


def _is_variadic_selector(selector: str) -> bool:
    """Whether `selector` names a method that takes a real (`…`) variable argument list."""
    return selector.endswith("Format:") or selector in _VARIADIC_SELECTORS


def _expected_arg_count(selector: str) -> int:
    """The true argument count of an `objc_msgSend` to `selector`: receiver + SEL + one per colon."""
    return _FIXED_ARGS + selector.count(":")


class msgsend_argcount_visitor_t(minsn_visitor_t, CounterMixin):
    """
    Drop the phantom trailing arguments from over-counted `objc_msgSend` calls.

    IDA types every dispatch helper as the variadic `id objc_msgSend(id, SEL, ...)`
    and guesses the variadic count from register liveness at the call site, which
    routinely over-counts (e.g. a zero-argument `-[x sharedInstance]` gathered with
    five extra args). The selector is exact, though: a non-variadic selector takes one
    argument per `:`. This trims any surplus call arguments back to that count.
    """

    def visit_minsn(self) -> int:
        insn: minsn_t = self.curins
        if insn.opcode == ida_hexrays.m_call:
            self._fix_call(insn)
        return 0

    def _fix_call(self, insn: minsn_t) -> None:
        if minsn.get_func_name_of_call(insn) not in MSGSEND_HELPERS:
            return

        call_info: mcallinfo_t | None = insn.d.f
        if call_info is None or len(call_info.args) <= _FIXED_ARGS:
            return

        selector = mop.get_str(call_info.args[1])
        if selector is None or _is_variadic_selector(selector):
            return

        expected = _expected_arg_count(selector)
        # Only ever truncate surplus arguments; never synthesize missing ones.
        if len(call_info.args) <= expected:
            return

        while len(call_info.args) > expected:
            call_info.args.pop_back()
        self.count()


class objc_msgsend_argcount_optimizer_t(ida_hexrays.optinsn_t):
    """Correct over-counted `objc_msgSend` argument lists once IDA has reconstructed the calls."""

    def func(self, blk: mblock_t, ins: minsn_t, optflags: int) -> int:
        # Wait for call reconstruction: before MMAT_CALLS the selector stubs have no
        # call info and their arguments are not yet gathered.
        if blk.mba.maturity < ida_hexrays.MMAT_CALLS:
            return 0

        visitor = msgsend_argcount_visitor_t(blk.mba, blk)
        ins.for_all_insns(visitor)
        if visitor.cnt:
            blk.mark_lists_dirty()
        return visitor.cnt
