__all__ = ["stub_call_optimizer_t"]

import ida_hexrays
from ida_hexrays import mblock_t, minsn_t, minsn_visitor_t, optinsn_t
from idahelper.dsc.stubs import DscStubCache

from ioshelper.base.utils import CounterMixin


class _RetargetVisitor(minsn_visitor_t, CounterMixin):
    """
    Retarget every call to a known stub so its callee becomes the canonical function.

    `for_all_insns` visits nested calls too (e.g. a call used as an `if` condition), so
    stub calls buried inside expressions are retargeted as well.
    """

    def __init__(self, cache: DscStubCache):
        super().__init__()
        self._cache = cache

    def visit_minsn(self) -> int:
        insn: minsn_t = self.curins
        if insn.opcode != ida_hexrays.m_call:
            return 0

        # A direct call names its target by global address.
        callee = insn.l
        if callee.t != ida_hexrays.mop_v:
            return 0

        target_ea = self._cache.target_for(callee.g)
        if target_ea is None:
            return 0

        size = callee.size
        callee.make_gvar(target_ea)
        callee.size = size
        self.count()
        return 0


class stub_call_optimizer_t(optinsn_t):
    """
    Rewrite dyld-shared-cache stub calls to point at the real, clean-named function.

    The shared stub cache builds lazily on first use, so the build runs after
    auto-analysis and is reused by every consumer (e.g. the xrefs action).
    """

    def func(self, blk: mblock_t, ins: minsn_t, optflags: int) -> int:
        # Wait for call reconstruction: before MMAT_CALLS the call targets aren't settled.
        if blk.mba.maturity < ida_hexrays.MMAT_CALLS:
            return 0

        visitor = _RetargetVisitor(DscStubCache.get())
        ins.for_all_insns(visitor)
        if visitor.cnt:
            blk.mark_lists_dirty()
        return visitor.cnt
