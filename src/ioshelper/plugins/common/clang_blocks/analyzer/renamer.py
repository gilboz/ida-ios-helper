"""
Propagate names and types between Clang block variables and their block types.

Capture fields take the name — and, when meaningful, the type — of the variable
assigned into them (`block.lvar2 = connection` -> `block.connection`); role-named
variables (`self`, `implicit_arg`) contribute a type-derived name instead. Block
variables without a better name get kind-based ones (`stack_block1`, `byref_block1`,
...), numbered per kind in declaration order.
"""

__all__ = ["rename_blocks_in_func"]

import re
from collections import Counter
from dataclasses import dataclass

import ida_hexrays
from ida_hexrays import cexpr_t, cfuncptr_t, lvar_t
from ida_typeinf import tinfo_t, udm_t
from idahelper import naming, tif
from idahelper.ast import cexpr, lvars
from idahelper.ast.lvars import VariableModification, is_default_name

from ioshelper.base.log import debug

from ..model.block_layout import (
    block_kind_from_init_helper,
    block_member_is_arg_field,
    get_block_type,
    get_isa,
    is_block_type,
)
from ..model.byref_layout import is_block_arg_byref_type
from ..model.field_assignments import StructFieldAssignment
from .options import CLANG_BLOCKS_ANALYZER_COMPONENT_NAME, BlocksAnalyzerOptions
from .scan import BlocksScan

# Names IDA's own stack-block analysis gives block variables (`block`, `blocka`,
# `block_4`, ...) — generic, so a kind-based name is an improvement.
_GENERIC_BLOCK_NAME = re.compile(r"^block(?:_?\d+|[a-z])?$")

# Names IDA's own stack-block analysis gives capture fields (`lvar0`, `lvar1`, ...) —
# any other name was set by the user or a previous run, and is left untouched.
_DEFAULT_FIELD_NAME = re.compile(r"^lvar\d+$")


@dataclass(frozen=True)
class _BlockVar:
    """
    One block variable of the function.

    Attributes:
        lvar: The block's local variable.
        kind: The block's kind: `stack`, `global`, `malloc`, `byref`, ...
        field_assignments: Assignments into the block's fields; only stack-built
            blocks have any.
    """

    lvar: lvar_t
    kind: str
    field_assignments: list[StructFieldAssignment]


def rename_blocks_in_func(scan: BlocksScan, options: BlocksAnalyzerOptions) -> bool:
    """
    Rename block capture fields and default-named block variables of a function.

    Args:
        scan: The function's block scan; must reflect the current decompilation —
            when an earlier step changed types the function uses, re-scan first.
        options: The gates selecting which of the analyses run.

    Returns:
        `True` if at least one field or variable was modified.
    """
    blocks = _collect_block_vars(scan)
    if not blocks:
        return False

    func = scan.func
    planned = _plan_block_names(func, blocks) if options.rename_blocks else {}
    new_names = {current: modification.name for current, modification in planned.items() if modification.name}

    changed = False
    if options.rename_fields or options.retype_fields:
        for block in blocks:
            changed |= _sync_block_fields(block, new_names, rename=options.rename_fields, retype=options.retype_fields)

    if planned:
        changed |= lvars.perform_lvar_modifications(func.entry_ea, func.get_lvars(), planned)
    return changed


# region collection
def _collect_block_vars(scan: BlocksScan) -> list[_BlockVar]:
    """
    Collect every block variable of the function, in declaration order.

    Stack-built blocks (struct-typed `Block_layout_*` lvars) carry their field
    assignments and derive their kind from the initialized isa; byref argument structs
    and pointers to global block literals only participate in block naming.
    """
    blocks: list[_BlockVar] = []
    for lvar in scan.func.get_lvars():
        lvar_type = lvar.type()
        if is_block_type(lvar_type):
            assignments = scan.field_assignments.get(lvar.name, [])
            kind = _stack_block_kind(assignments, scan.var_assignments.get(lvar.name, []))
            blocks.append(_BlockVar(lvar, kind, assignments))
        elif is_block_arg_byref_type(lvar_type):
            blocks.append(_BlockVar(lvar, "byref", []))
        elif any(_is_global_block_ref(expr) for expr in scan.var_assignments.get(lvar.name, [])):
            blocks.append(_BlockVar(lvar, "global", []))
    return blocks


def _stack_block_kind(field_assignments: list[StructFieldAssignment], init_exprs: list[cexpr_t]) -> str:
    """
    Derive a stack-built block's kind from its initialization.

    Reads the isa either from the raw `block.isa = &_NSConcreteStackBlock` field
    assignment or from the `_stack_block_init(...)` helper call the
    `clang-blocks-optimizer` hook rewrote it into. Falls back to `stack` — the block
    is stack-built, after all.
    """
    for assignment in field_assignments:
        if assignment.member.name == "isa" and (isa := get_isa(cexpr.strip_casts(assignment.expr))) is not None:
            kind = get_block_type(isa)
            if kind != "unknown":
                return kind
    for expr in init_exprs:
        expr = cexpr.strip_casts(expr)
        if expr.op == ida_hexrays.cot_call and expr.x.op == ida_hexrays.cot_helper:
            kind = block_kind_from_init_helper(expr.x.helper)
            if kind is not None:
                return kind
    return "stack"


def _is_global_block_ref(expr: cexpr_t) -> bool:
    """Whether the expression takes the address of a global block literal."""
    expr = cexpr.strip_casts(expr)
    if expr.op == ida_hexrays.cot_ref:
        return expr.x.op == ida_hexrays.cot_obj and is_block_type(expr.x.type)
    if expr.op == ida_hexrays.cot_obj:
        expr_type: tinfo_t = expr.type
        return expr_type.is_ptr() and is_block_type(expr_type.get_pointed_object())
    return False


def _assigned_variable(expr: cexpr_t) -> tuple[lvar_t, bool] | None:
    """The variable a field is assigned from: `(var, is_ref)` for `v` / `&v` rvalues, else `None`."""
    expr = cexpr.strip_casts(expr)
    if expr.op == ida_hexrays.cot_ref:
        expr = expr.x
        if expr.op != ida_hexrays.cot_var:
            return None
        return cexpr.getv(expr.v), True
    if expr.op == ida_hexrays.cot_var:
        return cexpr.getv(expr.v), False
    return None


# endregion


# region block variable naming
def _plan_block_names(func: cfuncptr_t, blocks: list[_BlockVar]) -> dict[str, VariableModification]:
    """
    Plan kind-based names (`stack_block1`, `byref_block1`, ...) for the blocks.

    Numbering starts at 1 per kind and follows declaration order. Blocks whose
    current name is worth keeping (see `_has_better_name`) are left alone.

    Returns:
        Mapping of current variable name to its planned modification.
    """
    taken = {lvar.name for lvar in func.get_lvars()}
    counters: Counter[str] = Counter()
    planned: dict[str, VariableModification] = {}
    for block in blocks:
        if _has_better_name(block.lvar):
            continue
        counters[block.kind] += 1
        name = naming.unique_name(f"{block.kind}_block{counters[block.kind]}", taken)
        taken.add(name)
        planned[block.lvar.name] = VariableModification(name=name)
    return planned


def _has_better_name(lvar: lvar_t) -> bool:
    """Whether the variable already carries a name worth keeping over a kind-based one."""
    if not lvar.has_user_name:
        return False
    return not is_default_name(lvar.name) and _GENERIC_BLOCK_NAME.match(lvar.name) is None


# endregion


# region capture fields
def _sync_block_fields(block: _BlockVar, new_names: dict[str, str], *, rename: bool, retype: bool) -> bool:
    """
    Rename/retype the capture fields of one block from the variables assigned to them.

    A field takes the effective name of its variable (see `_field_name`) unless that
    name is a default one. Types only propagate when meaningful (see `_retype_field`).

    A field the user (or a previous run) already named — its name is no longer a default
    `lvarN` — is left entirely alone: neither renamed nor retyped, so manual edits are
    never clobbered.

    Args:
        block: The block whose fields to update.
        new_names: The planned block renames, current name -> new name.
        rename: Whether to rename the fields.
        retype: Whether to retype the fields.

    Returns:
        `True` if at least one field was modified.
    """
    changed = False
    seen_offsets: set[int] = set()
    for assignment in block.field_assignments:
        if assignment.is_cast_assign or not block_member_is_arg_field(assignment.member):
            continue
        # A field written in several branches is synced from its first assignment only.
        if assignment.member.offset in seen_offsets:
            continue
        source = _assigned_variable(assignment.expr)
        if source is None:
            continue
        seen_offsets.add(assignment.member.offset)
        member = assignment.member
        if not _is_default_field_name(member.name):
            debug(f"{CLANG_BLOCKS_ANALYZER_COMPONENT_NAME}: keeping user-named field {assignment.type.get_type_name()}.{member.name}")
            continue
        var, is_ref = source
        if rename:
            changed |= _rename_field(assignment.type, member, _field_name(var, new_names))
        if retype:
            changed |= _retype_field(assignment.type, member, var, is_ref=is_ref)
    return changed


def _is_default_field_name(name: str) -> bool:
    """Whether `name` is a name IDA auto-gave a capture field (`lvar0`, `lvar1`, ...)."""
    return _DEFAULT_FIELD_NAME.match(name) is not None


# Variable names that state the variable's role, not its content — a capture field
# named after them says nothing, so a type-derived name is preferred.
_ROLE_NAMED_VARS = frozenset({"self", "implicit_arg"})


def _field_name(var: lvar_t, new_names: dict[str, str]) -> str:
    """
    The name a capture field takes from the variable assigned into it.

    The planned kind-based name when the variable is itself a block being renamed;
    for role-named variables (`self`, `implicit_arg`) a name derived from the
    variable's type, when one is available.
    """
    name = new_names.get(var.name, var.name)
    if name in _ROLE_NAMED_VARS:
        return _name_from_type(var.type()) or name
    return name


def _name_from_type(var_type: tinfo_t) -> str | None:
    """A snake_case name from the pointed-to type's name (`IDSDaemonController *` -> `ids_daemon_controller`)."""
    if not var_type.is_ptr():
        return None
    type_name = var_type.get_pointed_object().get_type_name()
    if type_name is None or type_name in ("objc_object", "objc_class"):  # `id` / `Class` — meaningless
        return None
    return naming.camel_to_snake(type_name)


def _rename_field(struct_type: tinfo_t, member: udm_t, wanted: str) -> bool:
    """
    Rename `member` of `struct_type` after the variable assigned into it.

    Default variable names (`v12`) are never propagated to fields; a name that collides
    with another field is disambiguated by `tif.rename_udm_unique`.

    Returns:
        `True` if the field was renamed.
    """
    if is_default_name(wanted) or wanted == member.name:
        return False
    old_name = member.name
    name = tif.rename_udm_unique(struct_type, member, wanted)
    if name is None:
        print(f"[Error] Failed to rename field {member.name} of {struct_type.get_type_name()} to {wanted}")
        return False
    member.name = name
    debug(f"{CLANG_BLOCKS_ANALYZER_COMPONENT_NAME}: renamed field {struct_type.get_type_name()}.{old_name} -> {name}")
    return True


def _retype_field(struct_type: tinfo_t, member: udm_t, var: lvar_t, *, is_ref: bool) -> bool:
    """
    Set the type of `member` of `struct_type` from the variable assigned into it.

    Only meaningful variable types propagate: a type the user set, or an argument's
    type (it comes from the function prototype). A `&v` assignment propagates a
    pointer to the variable's type. The field's size is never changed, so the block
    layout stays intact.

    Returns:
        `True` if the field was retyped.
    """
    if not (var.has_user_type or var.is_arg_var):
        return False
    var_type = var.type()
    new_type = tif.pointer_of(var_type) if is_ref else var_type
    if new_type.get_size() * 8 != member.size or member.type == new_type:
        return False
    if not tif.set_udm_type(struct_type, member, new_type):
        print(f"[Error] Failed to set type {new_type} for field {member.name} of {struct_type.get_type_name()}")
        return False
    debug(f"{CLANG_BLOCKS_ANALYZER_COMPONENT_NAME}: retyped field {struct_type.get_type_name()}.{member.name} -> {new_type.dstr()}")
    return True


# endregion
