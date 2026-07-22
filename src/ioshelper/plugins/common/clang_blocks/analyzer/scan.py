"""
One-pass scan of the block-related facts of a decompiled function.

`BlocksScan` gathers the block lvars, their field assignments, and the whole-variable
assignments in a single ctree traversal, so the pipeline steps share one collection.
"""

__all__ = ["BlocksScan"]

from dataclasses import dataclass
from typing import Self

import ida_hexrays
from ida_hexrays import cexpr_t, cfuncptr_t, lvar_t
from idahelper.ast import cfunc
from idahelper.ast.cexpr import getv

from ..model.block_layout import get_ida_block_lvars
from ..model.field_assignments import LvarFieldsAssignmentsCollector, StructFieldAssignment


class _ScanCollector(LvarFieldsAssignmentsCollector):
    """
    Collect block-field assignments and whole-variable assignments in one traversal.

    Extends the field collector with `v = <expr>` assignments (kept for every
    variable, not just blocks — the renamer needs them to spot global block refs).
    """

    def __init__(self, target_lvars: list[lvar_t]) -> None:
        super().__init__(target_lvars)
        self.var_assignments: dict[str, list[cexpr_t]] = {}

    def visit_expr(self, exp: cexpr_t) -> int:
        # A bare-variable lvalue is a whole-variable assignment — never a field one.
        if exp.op == ida_hexrays.cot_asg and exp.x.op == ida_hexrays.cot_var:
            self.var_assignments.setdefault(getv(exp.x.v).name, []).append(exp.y)
            return 0
        return super().visit_expr(exp)


@dataclass(frozen=True, slots=True)
class BlocksScan:
    """
    The block-related facts of one decompiled function, collected in a single pass.

    Attributes:
        func: The decompiled function the facts were read from.
        block_lvars: The function's `Block_layout_*`-typed local variables.
        field_assignments: `block.field = <expr>` assignments into those variables,
            keyed by variable name.
        var_assignments: `v = <expr>` whole-variable assignments, keyed by variable
            name — for every variable, not just blocks.
    """

    func: cfuncptr_t
    block_lvars: list[lvar_t]
    field_assignments: dict[str, list[StructFieldAssignment]]
    var_assignments: dict[str, list[cexpr_t]]

    @classmethod
    def from_func(cls, func: cfuncptr_t) -> Self:
        """
        Scan an already-decompiled function.

        Args:
            func: The decompiled function.

        Returns:
            The collected scan.
        """
        block_lvars = get_ida_block_lvars(func)
        collector = _ScanCollector(block_lvars)
        collector.apply_to(func.body, None)  # pyright: ignore[reportArgumentType]
        return cls(
            func=func,
            block_lvars=block_lvars,
            field_assignments=collector.assignments,
            var_assignments=collector.var_assignments,
        )

    @classmethod
    def from_ea(cls, ea: int, *, refresh: bool = False) -> Self | None:
        """
        Decompile the function at `ea` and scan it.

        Args:
            ea: An address inside the function.
            refresh: Invalidate the cached decompilation first, forcing a fresh one —
                needed when an earlier step changed types the function uses.

        Returns:
            The collected scan, or `None` when decompilation failed.
        """
        if refresh:
            cfunc.mark_dirty(ea)
        func = cfunc.from_ea(ea)
        if func is None:
            return None
        return cls.from_func(func)
