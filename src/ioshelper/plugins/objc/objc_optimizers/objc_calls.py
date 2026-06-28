__all__ = ["objc_calls_optimizer_t"]

from ida_hexrays import minsn_t, mop_t

from ._base import CallInsnVisitor, CallMopVisitor, CallOptimizer
from ._match import match_func_name

# Retain-style helpers that lower to `mov` but are NOT covered by IDA's built-in ARC folding,
# so they are stripped on every IDA version.
REPLACE_WITH_ARG_FUNCTIONS: list[str] = [
    # Blocks
    "objc_retainBlock",
    # Swift
    "swift_bridgeObjectRetain",
]

# Single-argument void helpers that lower to `nop`.
VOID_FUNCTIONS_TO_REMOVE_WITH_SINGLE_ARG: list[str] = [
    # intrinsics
    "break",
    # Swift
    "swift_bridgeObjectRelease",
]

# Multi-argument void helpers that lower to `nop`.
VOID_FUNCTIONS_TO_REMOVE_WITH_MULTIPLE_ARGS: list[str] = [
    # Blocks
    "Block_object_dispose",
]


class _CallsMopVisitor(CallMopVisitor):
    def handle_call(self, op: mop_t, insn: minsn_t, name: str) -> None:
        if match_func_name(REPLACE_WITH_ARG_FUNCTIONS, name):
            self.replace_with_first_arg(op, insn, name)


class _CallsInsnVisitor(CallInsnVisitor):
    def handle_call(self, insn: minsn_t, name: str) -> None:
        if match_func_name(VOID_FUNCTIONS_TO_REMOVE_WITH_SINGLE_ARG, name):
            self.try_remove_call(insn, name=name, exact_arg_count=1, require_void_return=True)
        elif match_func_name(VOID_FUNCTIONS_TO_REMOVE_WITH_MULTIPLE_ARGS, name):
            self.try_remove_call(insn, name=name, exact_arg_count=None, require_void_return=True)
        elif match_func_name(REPLACE_WITH_ARG_FUNCTIONS, name):
            self.replace_with_first_arg(insn, name)


class objc_calls_optimizer_t(CallOptimizer):
    """Fold the non-ARC retain/release-style helpers (blocks, Swift bridge, intrinsics) into mov/nop."""

    mop_visitor_cls = _CallsMopVisitor
    insn_visitor_cls = _CallsInsnVisitor
