"""
Automatically run the block analysis the first time a block function is shown in a view.

`BlocksAutoAnalyzeHook` (GUI-only, gated by the `auto` option) listens to
`open_pseudocode` / `switch_pseudocode` — deliberately not `maturity`, which also fires
for programmatic decompilations that must not mutate the database as a side effect.
The pipeline is deferred to the UI request queue because it re-decompiles the function,
and each function runs at most once, gated by the pipeline's persisted netnode marker.
The first view's text is pre-analysis; a refresh shows the result.
"""

__all__ = ["BlocksAutoAnalyzeHook", "function_uses_blocks"]

import functools
from typing import Self

import ida_hexrays
import ida_kernwin
from ida_hexrays import cexpr_t, cfuncptr_t, vdui_t
from idahelper import memory, runtime

from ..model.block_layout import BLOCK_TYPES, is_block_type
from ..model.byref_layout import is_block_arg_byref_type
from .options import BlocksAnalyzerOptions
from .pipeline import analyze_blocks_in_func, is_func_block_analyzed


def function_uses_blocks(func: cfuncptr_t) -> bool:
    """
    Whether the decompiled function shows block artifacts the analysis can act on.

    Both pre-analysis artifacts (raw `_NSConcrete*Block` isa references, global block
    literals) and post-analysis ones (`Block_layout_*` / byref-struct variables) count.
    The caller gates on the persisted analyzed-marker first, so this only runs for
    functions not yet analyzed by any session.
    """
    for lvar in func.get_lvars():
        lvar_type = lvar.type()
        if is_block_type(lvar_type) or is_block_arg_byref_type(lvar_type):
            return True
    finder = _BlockArtifactFinder()
    finder.apply_to(func.body, None)  # pyright: ignore[reportArgumentType]
    return finder.found


class _BlockArtifactFinder(ida_hexrays.ctree_visitor_t):
    """Stops at the first global reference betraying a block: an isa or a block literal."""

    def __init__(self) -> None:
        super().__init__(ida_hexrays.CV_FAST)
        self.found = False

    def visit_expr(self, expr: cexpr_t) -> int:
        if expr.op != ida_hexrays.cot_obj:
            return 0
        expr_type = expr.type
        if memory.name_from_ea(expr.obj_ea) in BLOCK_TYPES or is_block_type(expr_type) or (expr_type.is_ptr() and is_block_type(expr_type.get_pointed_object())):
            self.found = True
            return 1
        return 0


class BlocksAutoAnalyzeHook(ida_hexrays.Hexrays_Hooks):
    """
    Queue the block analysis the first time a block function is shown in a view.

    Args:
        options: The `[clang-blocks-analyzer]` step gates, the same ones the manual
            action honors — resolved by the component and passed in.
    """

    def __init__(self, options: BlocksAnalyzerOptions) -> None:
        super().__init__()
        self._options = options

    @classmethod
    def build(cls, options: BlocksAnalyzerOptions) -> Self | None:
        """
        Build the hook, or `None` when headless or the section's `auto` option is off.

        The gated factory the auto-analyzer component installs (returning `None` makes
        the component install nothing). GUI-only: the deferred pipeline run needs the
        UI event loop.

        Args:
            options: The `[clang-blocks-analyzer]` section, resolved by the component.

        Returns:
            The hook when running in the GUI with `auto` enabled, else `None`.
        """
        return cls(options) if options.auto and not runtime.is_headless() else None

    def open_pseudocode(self, vu: vdui_t) -> int:
        self._on_func_ready(vu.cfunc)
        return 0

    def switch_pseudocode(self, vu: vdui_t) -> int:
        self._on_func_ready(vu.cfunc)
        return 0

    def _on_func_ready(self, func: cfuncptr_t | None) -> None:
        """Queue the analysis for a not-yet-analyzed block function on the UI event loop."""
        if func is None:
            return
        ea = func.entry_ea
        if is_func_block_analyzed(ea):
            return
        if function_uses_blocks(func):
            # Unsafe to run inside the hexrays event (the pipeline re-decompiles). A truthy
            # "changed" return re-queues once; the re-run hits the marker and ends the chain.
            ida_kernwin.execute_ui_requests([functools.partial(analyze_blocks_in_func, ea, self._options, force=False)])
