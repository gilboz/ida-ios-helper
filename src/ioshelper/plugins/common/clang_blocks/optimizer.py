"""
The `clang-blocks-optimizer` hexrays hook.

At each decompilation it collapses the runs of block / byref-struct field-assignment
statements into single `_..._block_init(...)` / `_byref_block_arg_init(...)` helper
calls, so the pseudocode reads as one initialization per block.
"""

import ida_hexrays
from ida_hexrays import Hexrays_Hooks, cexpr_t, cfuncptr_t, cinsn_t
from idahelper.ast import cexpr, cinsn, citem

from .model.block_layout import (
    BlockBaseFieldsAssignments,
    block_init_helper_name,
    get_block_type,
    get_ida_block_lvars,
    get_isa,
)
from .model.byref_layout import BlockByRefArgBaseFieldsAssignments, get_block_byref_args_lvars
from .model.field_assignments import StructFieldAssignment, get_struct_fields_assignments


class objc_blocks_optimizer_hooks_t(Hexrays_Hooks):
    def maturity(self, func: cfuncptr_t, new_maturity: int) -> int:
        if new_maturity < ida_hexrays.CMAT_CPA:
            return 0

        optimize_blocks(func)
        optimize_block_byref_args(func)
        return 0


def replace_first_and_cleanup(assignments: list[cinsn_t], new_insn: cinsn_t) -> None:
    """
    Collapse a run of block field-assignment statements into `new_insn`.

    The first statement is replaced in place by `new_insn` and the rest are emptied.
    `swap_preserving_label` keeps any `goto`-target label on the first statement (see it for
    the INTERR 50728 rationale); `cleanup` preserves `label_num`, so labels on the emptied
    statements survive on their own.
    """
    first_assignment, *rest = assignments
    for assignment in rest:
        assignment.cleanup()
    citem.swap_preserving_label(first_assignment, new_insn)


# region byref args
def optimize_block_byref_args(func: cfuncptr_t) -> bool:
    byref_lvars = get_block_byref_args_lvars(func)
    if not byref_lvars:
        return False

    assignments = get_struct_fields_assignments(func, byref_lvars)
    has_optimized = False
    for lvar, lvar_assignments in assignments.items():
        has_optimized |= optimize_block_byref_arg(lvar, func, lvar_assignments)

    return has_optimized


def optimize_block_byref_arg(lvar: str, func: cfuncptr_t, assignments: list[StructFieldAssignment]) -> bool:
    byref_fields = BlockByRefArgBaseFieldsAssignments.initial()
    for assignment in assignments:
        byref_fields.add_assignment(assignment)

    if not byref_fields.is_completed():
        return False

    new_insn = create_byref_init_insn(lvar, func, byref_fields)
    replace_first_and_cleanup(byref_fields.assignments, new_insn)
    return True


def create_byref_init_insn(lvar: str, func: cfuncptr_t, byref_fields: BlockByRefArgBaseFieldsAssignments) -> cinsn_t:
    if byref_fields.byref_dispose is not None:
        call = cexpr.call_helper_from_sig(
            "_byref_block_arg_ex_init",
            byref_fields.type,
            [
                cexpr_t(byref_fields.flags),
                cexpr_t(byref_fields.byref_keep),
                cexpr_t(byref_fields.byref_dispose),
            ],
        )
    else:
        call = cexpr.call_helper_from_sig(
            "_byref_block_arg_init",
            byref_fields.type,
            [
                cexpr_t(byref_fields.flags),
            ],
        )

    lvar_exp = cexpr.from_var_name(lvar, func)

    return cinsn.from_expr(cexpr.from_assignment(lvar_exp, call), ea=byref_fields.ea)


# endregion


# region blocks
def optimize_blocks(func: cfuncptr_t) -> bool:
    block_lvars = get_ida_block_lvars(func)
    if not block_lvars:
        return False

    assignments = get_struct_fields_assignments(func, block_lvars)
    has_optimized = False
    for lvar, lvar_assignments in assignments.items():
        has_optimized |= optimize_block(lvar, func, lvar_assignments)

    return has_optimized


def optimize_block(lvar: str, func: cfuncptr_t, assignments: list[StructFieldAssignment]) -> bool:
    block_fields = BlockBaseFieldsAssignments.initial()
    for assignment in assignments:
        block_fields.add_assignment(assignment)

    if not block_fields.is_completed():
        return False

    new_insn = create_block_init_insn(lvar, func, block_fields)
    replace_first_and_cleanup(block_fields.assignments, new_insn)
    return True


def create_block_init_insn(lvar: str, func: cfuncptr_t, block_fields: BlockBaseFieldsAssignments) -> cinsn_t:
    if (isa := get_isa(block_fields.isa)) is not None:
        call = cexpr.call_helper_from_sig(
            block_init_helper_name(get_block_type(isa)),
            block_fields.type,
            [
                cexpr_t(block_fields.flags),
                cexpr_t(block_fields.descriptor),
                cexpr_t(block_fields.invoke),
            ],
        )
    else:
        call = cexpr.call_helper_from_sig(
            block_init_helper_name(None),
            block_fields.type,
            [
                cexpr_t(block_fields.isa),
                cexpr_t(block_fields.flags),
                cexpr_t(block_fields.descriptor),
                cexpr_t(block_fields.invoke),
            ],
        )

    lvar_exp = cexpr.from_var_name(lvar, func)

    return cinsn.from_expr(cexpr.from_assignment(lvar_exp, call), ea=block_fields.ea)


# endregion
