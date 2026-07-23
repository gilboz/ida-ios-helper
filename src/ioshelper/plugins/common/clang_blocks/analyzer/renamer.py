"""
Propagate names and types between Clang block variables and their block types.

Capture fields take the name — and, when meaningful, the type — of the variable
assigned into them (`block.lvar2 = connection` -> `block.connection`); role-named
variables (`self`, `implicit_arg`) contribute a type-derived name instead, and a
capture copied from another struct's field (`block.lvar4 = v->topic`) takes that
field's name and type. Block
variables without a better name get kind-based ones (`stack_block1`, `byref_block1`,
...), numbered per kind in declaration order.
"""

__all__ = ["rename_blocks_in_func"]

import re
from collections import Counter
from dataclasses import dataclass
from typing import Self

import ida_hexrays
from ida_hexrays import cexpr_t, cfuncptr_t, lvar_t
from ida_typeinf import tinfo_t, udm_t
from idahelper import naming, tif
from idahelper.ast import cexpr, lvars
from idahelper.ast.lvars import VariableModification, is_default_name
from idahelper.ast.struct_assignments import StructFieldAssignment

from ioshelper.base.log import debug

from ..model.block_layout import (
    block_kind_from_init_helper,
    block_member_is_arg_field,
    get_block_type,
    get_isa,
    is_block_type,
)
from ..model.byref_layout import is_block_arg_byref_type
from .options import CLANG_BLOCKS_ANALYZER_COMPONENT_NAME, BlocksAnalyzerOptions
from .scan import BlocksScan

# Names IDA's own stack-block analysis gives block variables (`block`, `blocka`,
# `block_4`, ...) — generic, so a kind-based name is an improvement.
_GENERIC_BLOCK_NAME = re.compile(r"^block(?:_?\d+|[a-z])?$")

# Variable names that state the variable's role, not its content — a capture field
# named after them says nothing, so a type-derived name is preferred.
_ROLE_NAMED_VARS = frozenset({"self", "implicit_arg"})


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
    func = scan.func
    blocks = _BlockVar.collect(scan)
    if not blocks:
        debug(f"{CLANG_BLOCKS_ANALYZER_COMPONENT_NAME}: {func.entry_ea:#x}: no block variables")
        return False
    debug(f"{CLANG_BLOCKS_ANALYZER_COMPONENT_NAME}: {func.entry_ea:#x}: {len(blocks)} block variable(s): {', '.join(f'{block.lvar.name} ({block.kind})' for block in blocks)}")

    planned = _plan_block_names(func, blocks) if options.rename_blocks else {}
    if planned:
        debug(f"{CLANG_BLOCKS_ANALYZER_COMPONENT_NAME}: planned block renames: " + ", ".join(f"{current} -> {modification.name}" for current, modification in planned.items()))

    changed = False
    if options.rename_fields or options.retype_fields:
        new_names = {current: modification.name for current, modification in planned.items() if modification.name}
        syncer = _FieldSyncer(new_names, rename=options.rename_fields, retype=options.retype_fields)
        for block in blocks:
            changed |= syncer.sync(block)

    if planned:
        changed |= lvars.perform_lvar_modifications(func.entry_ea, func.get_lvars(), planned)
    return changed


# region collection
@dataclass(frozen=True, slots=True)
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

    @classmethod
    def collect(cls, scan: BlocksScan) -> list[Self]:
        """
        Collect every block variable of the function, in declaration order.

        Stack-built blocks (struct-typed `Block_layout_*` lvars) carry their field
        assignments and derive their kind from the initialized isa; byref argument
        structs and pointers to global block literals only participate in block naming.
        """
        return [block for lvar in scan.func.get_lvars() if (block := cls._classify(lvar, scan)) is not None]

    @classmethod
    def _classify(cls, lvar: lvar_t, scan: BlocksScan) -> Self | None:
        """Build the block variable `lvar` is, or `None` when it is not one."""
        lvar_type = lvar.type()
        if is_block_type(lvar_type):
            assignments = scan.field_assignments.get(lvar.name, [])
            kind = cls._stack_block_kind(assignments, scan.var_assignments.get(lvar.name, []))
            return cls(lvar, kind, assignments)
        if is_block_arg_byref_type(lvar_type):
            return cls(lvar, "byref", [])
        if any(_is_global_block_ref(expr) for expr in scan.var_assignments.get(lvar.name, [])):
            return cls(lvar, "global", [])
        return None

    @staticmethod
    def _stack_block_kind(field_assignments: list[StructFieldAssignment], init_exprs: list[cexpr_t]) -> str:
        """
        Derive a stack-built block's kind from its initialization.

        Reads the isa either from the raw `block.isa = &_NSConcreteStackBlock` field
        assignment or from the `_stack_block_init(...)` helper call the
        `clang-blocks-optimizer` hook rewrote it into. Falls back to `stack` — the
        block is stack-built, after all.
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

    @property
    def has_better_name(self) -> bool:
        """Whether the variable already carries a name worth keeping over a kind-based one."""
        if not self.lvar.has_user_name:
            return False
        return not is_default_name(self.lvar.name) and _GENERIC_BLOCK_NAME.match(self.lvar.name) is None


def _is_global_block_ref(expr: cexpr_t) -> bool:
    """Whether the expression takes the address of a global block literal."""
    expr = cexpr.strip_casts(expr)
    if expr.op == ida_hexrays.cot_ref:
        return expr.x.op == ida_hexrays.cot_obj and is_block_type(expr.x.type)
    if expr.op == ida_hexrays.cot_obj:
        expr_type: tinfo_t = expr.type
        return expr_type.is_ptr() and is_block_type(expr_type.get_pointed_object())
    return False


# endregion


# region block variable naming
def _plan_block_names(func: cfuncptr_t, blocks: list[_BlockVar]) -> dict[str, VariableModification]:
    """
    Plan kind-based names (`stack_block1`, `byref_block1`, ...) for the blocks.

    Numbering starts at 1 per kind and follows declaration order. Blocks whose
    current name is worth keeping (see `_BlockVar.has_better_name`) are left alone.

    Returns:
        Mapping of current variable name to its planned modification.
    """
    taken = {lvar.name for lvar in func.get_lvars()}
    counters: Counter[str] = Counter()
    planned: dict[str, VariableModification] = {}
    for block in blocks:
        if block.has_better_name:
            continue
        counters[block.kind] += 1
        name = naming.unique_name(f"{block.kind}_block{counters[block.kind]}", taken)
        taken.add(name)
        planned[block.lvar.name] = VariableModification(name=name)
    return planned


# endregion


# region capture fields
@dataclass(frozen=True, slots=True)
class _FieldSource:
    """
    What a capture field takes from the rvalue assigned into it.

    Attributes:
        name: The name the field takes, or `None` when the source carries no
            meaningful one.
        type: The type the field takes, or `None` when the source's type should
            not propagate.
    """

    name: str | None
    type: tinfo_t | None

    @classmethod
    def from_member_read(cls, expr: cexpr_t) -> Self | None:
        """
        The name/type a `p->field` rvalue contributes: the pointed-to member's.

        A source member still carrying a default `lvarN` name has nothing meaningful
        to contribute — its type is as auto-given as its name — so it contributes no
        source at all.
        """
        resolved = cexpr.memptr_member(expr)
        if resolved is None:
            return None
        _, member = resolved
        if tif.is_default_udm_name(member.name):
            return None
        return cls(name=member.name, type=tinfo_t(member.type))


@dataclass(frozen=True, slots=True)
class _CaptureField:
    """
    One capture field of a block's layout struct.

    Attributes:
        struct_type: The block's `Block_layout_*` struct type.
        member: The field itself.
    """

    struct_type: tinfo_t
    member: udm_t

    def __str__(self) -> str:
        return f"{self._struct_name}.{self.member.name}"

    @property
    def has_default_name(self) -> bool:
        """Whether the field still carries a name IDA auto-gave it (`lvar0`, `lvar1`, ...)."""
        return tif.is_default_udm_name(self.member.name)

    def rename(self, wanted: str) -> bool:
        """
        Rename the field to `wanted`.

        A name that collides with another field is disambiguated by
        `tif.rename_udm_unique`; a field already named `wanted` is left alone.

        Returns:
            `True` if the field was renamed.
        """
        if wanted == self.member.name:
            return False
        old_name = self.member.name
        name = tif.rename_udm_unique(self.struct_type, self.member, wanted)
        if name is None:
            print(f"[Error] Failed to rename field {self.member.name} of {self._struct_name} to {wanted}")
            return False
        self.member.name = name
        debug(f"{CLANG_BLOCKS_ANALYZER_COMPONENT_NAME}: renamed field {self._struct_name}.{old_name} -> {name}")
        return True

    def retype(self, new_type: tinfo_t) -> bool:
        """
        Set the field's type to `new_type`.

        The field's size is never changed, so the block layout stays intact; a field
        already of `new_type` is left alone.

        Returns:
            `True` if the field was retyped.
        """
        if new_type.get_size() * 8 != self.member.size or self.member.type == new_type:
            return False
        if not tif.set_udm_type(self.struct_type, self.member, new_type):
            print(f"[Error] Failed to set type {new_type} for field {self.member.name} of {self._struct_name}")
            return False
        debug(f"{CLANG_BLOCKS_ANALYZER_COMPONENT_NAME}: retyped field {self._struct_name}.{self.member.name} -> {new_type.dstr()}")
        return True

    @property
    def _struct_name(self) -> str | None:
        return self.struct_type.get_type_name()


class _FieldSyncer:
    """
    Renames/retypes the capture fields of blocks from what is assigned into them.

    One instance serves one rename run: it carries the run's planned block renames and
    option gates, so classifying an assignment's rvalue needs no extra arguments.
    """

    def __init__(self, new_names: dict[str, str], *, rename: bool, retype: bool) -> None:
        """
        Args:
            new_names: The planned block renames, current name -> new name.
            rename: Whether to rename the fields.
            retype: Whether to retype the fields.
        """
        self._new_names = new_names
        self._rename = rename
        self._retype = retype

    def sync(self, block: _BlockVar) -> bool:
        """
        Rename/retype the capture fields of one block.

        Each assignment's rvalue is classified once into the name and type it
        contributes (see `_classify_source`); the field takes the contributed name and
        type, as far as the syncer's gates allow.

        A field the user (or a previous run) already named — its name is no longer a
        default `lvarN` — is left entirely alone: neither renamed nor retyped, so
        manual edits are never clobbered.

        Args:
            block: The block whose fields to update.

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
            source = self._classify_source(assignment.expr)
            if source is None:
                continue
            seen_offsets.add(assignment.member.offset)
            field = _CaptureField(assignment.type, assignment.member)
            if not field.has_default_name:
                debug(f"{CLANG_BLOCKS_ANALYZER_COMPONENT_NAME}: keeping user-named field {field}")
                continue
            if self._rename and source.name is not None:
                changed |= field.rename(source.name)
            if self._retype and source.type is not None:
                changed |= field.retype(source.type)
        return changed

    def _classify_source(self, expr: cexpr_t) -> _FieldSource | None:
        """
        Classify a capture assignment's rvalue into the name/type it contributes.

        Branches on the expression kind: variables (`v`, `&v`) contribute per
        `_variable_source`, struct-field reads (`p->field`) per
        `_FieldSource.from_member_read`, any other rvalue nothing. A new source kind
        is a new branch returning a `_FieldSource`.
        """
        expr = cexpr.strip_casts(expr)
        if expr.op == ida_hexrays.cot_var:
            return self._variable_source(cexpr.getv(expr.v), is_ref=False)
        if expr.op == ida_hexrays.cot_ref and expr.x.op == ida_hexrays.cot_var:
            return self._variable_source(cexpr.getv(expr.x.v), is_ref=True)
        if expr.op == ida_hexrays.cot_memptr:
            return _FieldSource.from_member_read(expr)
        return None

    def _variable_source(self, var: lvar_t, *, is_ref: bool) -> _FieldSource:
        """
        The name/type a `v` or `&v` rvalue contributes: the variable's.

        The variable's effective name (see `_capture_name`) is contributed unless it
        is a default one. Its type is contributed only when meaningful — the user set
        it, or the variable is an argument (its type comes from the function
        prototype); a `&v` rvalue contributes a pointer to it.
        """
        name = self._capture_name(var)
        var_type: tinfo_t | None = None
        if var.has_user_type or var.is_arg_var:
            var_type = tif.pointer_of(var.type()) if is_ref else var.type()
        return _FieldSource(name=None if is_default_name(name) else name, type=var_type)

    def _capture_name(self, var: lvar_t) -> str:
        """
        The name a capture field takes from the variable assigned into it.

        The planned kind-based name when the variable is itself a block being renamed;
        for role-named variables (`self`, `implicit_arg`) a name derived from the
        variable's type, when one is available.
        """
        name = self._new_names.get(var.name, var.name)
        if name in _ROLE_NAMED_VARS:
            return naming.name_for_pointer_type(var.type()) or name
        return name


# endregion
