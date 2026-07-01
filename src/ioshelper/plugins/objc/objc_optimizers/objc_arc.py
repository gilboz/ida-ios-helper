__all__ = ["objc_arc_optimizer_t"]

from ida_hexrays import minsn_t, mop_t

from ._base import CallInsnVisitor, CallMopVisitor, CallOptimizer
from ._match import match_func_name

# ARC retain/autorelease/claim helpers that lower to `mov` (they return their argument unchanged).
RETAIN_FUNCTIONS: list[str] = [
    "objc_retain",
    "objc_retainAutorelease",
    "objc_autoreleaseReturnValue",
    "objc_autorelease",
    "objc_claimAutoreleasedReturnValue",
    "objc_unsafeClaimAutoreleasedReturnValue",
    "objc_retainAutoreleasedReturnValue",
]

# ARC release helper that lowers to `nop`.
RELEASE_FUNCTIONS: list[str] = [
    "objc_release",
]


class _ArcMopVisitor(CallMopVisitor):
    def handle_call(self, op: mop_t, insn: minsn_t, name: str) -> None:
        if match_func_name(RETAIN_FUNCTIONS, name):
            self.replace_with_first_arg(op, insn, name)


class _ArcInsnVisitor(CallInsnVisitor):
    def handle_call(self, insn: minsn_t, name: str) -> None:
        if match_func_name(RELEASE_FUNCTIONS, name):
            self.try_remove_call(insn, name=name, exact_arg_count=1, require_void_return=True)
        elif match_func_name(RETAIN_FUNCTIONS, name):
            self.replace_with_first_arg(insn, name)


class objc_arc_optimizer_t(CallOptimizer):
    """
    Fold the canonical ARC retain/release/autorelease/claim helpers into mov/nop.

    This is exactly the set IDA 9.4's built-in "hide Obj-C ARC calls" feature handles, so it is
    skipped on IDA >= 9.4 (see this package's `__init__`).
    """

    mop_visitor_cls = _ArcMopVisitor
    insn_visitor_cls = _ArcInsnVisitor
