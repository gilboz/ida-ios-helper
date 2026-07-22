__all__ = [
    "FLAG_BLOCK_HAS_COPY_DISPOSE",
    "BlockBaseFieldsAssignments",
    "block_init_helper_name",
    "block_kind_from_init_helper",
    "block_member_is_arg_field",
    "get_block_type",
    "get_ida_block_lvars",
    "get_isa",
    "is_block_type",
]

import re
from dataclasses import dataclass

import ida_hexrays
from ida_hexrays import (
    cexpr_t,
    cfuncptr_t,
    cinsn_t,
    lvar_t,
)
from ida_typeinf import tinfo_t, udm_t
from idahelper import memory
from idahelper.ast import cexpr

from .field_assignments import StructFieldAssignment

IDA_BLOCK_TYPE_NAME_PREFIX = "Block_layout_"
IDA_BLOCK_TYPE_BASE_FIELD_NAMES = {
    "isa",
    "flags",
    "reserved",
    "invoke",
    "descriptor",
}

FLAG_BLOCK_HAS_COPY_DISPOSE = 1 << 25


def get_ida_block_lvars(func: cfuncptr_t) -> list[lvar_t]:
    """Get all Obj-C block variables in the function"""
    return [lvar for lvar in func.get_lvars() if is_block_type(lvar.type())]


def is_block_type(tinfo: tinfo_t) -> bool:
    """Check if the type is an Obj-C block type"""
    if not tinfo.is_struct():
        return False
    # noinspection PyTypeChecker
    name: str | None = tinfo.get_type_name()
    return name is not None and name.startswith(IDA_BLOCK_TYPE_NAME_PREFIX)


def block_member_is_arg_field(udm: udm_t) -> bool:
    """Check if the member is an argument field of an Obj-C block"""
    return udm.name not in IDA_BLOCK_TYPE_BASE_FIELD_NAMES


BLOCK_TYPES: dict[str, str] = {}
for typ in ["stack", "global", "malloc", "auto", "finalizing", "weak"]:
    typ_cap = typ.capitalize()
    BLOCK_TYPES[f"_NSConcrete{typ_cap}Block"] = typ
    BLOCK_TYPES[f"__NSConcrete{typ_cap}Block"] = typ
    BLOCK_TYPES[f"__NSConcrete{typ_cap}Block_ptr"] = typ
    BLOCK_TYPES[f"_OBJC_CLASS_$___NS{typ_cap}Block__"] = typ


def get_block_type(isa: str) -> str:
    """Get the block type from the isa symbol"""
    return BLOCK_TYPES.get(isa, "unknown")


# The `clang-blocks-optimizer` hook collapses a block initialization into a helper call
# named after the block kind: `_stack_block_init(...)`, `_global_block_init(...)`, or a
# bare `_block_init(...)` (keeping the isa as an argument) when it could not be read.
_BLOCK_INIT_HELPER = re.compile(r"^_(?:(\w+)_)?block_init$")


def block_init_helper_name(kind: str | None) -> str:
    """
    Get the `clang-blocks-optimizer` init-helper name for a block of the given `kind`.

    Args:
        kind: The `get_block_type` result (`stack`, `global`, `unknown`, ...), or `None`
            when the isa could not be read — which yields the bare `_block_init` that keeps
            the isa as an explicit argument.

    Returns:
        The helper name, e.g. `_stack_block_init` or `_block_init`.
    """
    return "_block_init" if kind is None else f"_{kind}_block_init"


def block_kind_from_init_helper(name: str) -> str | None:
    """
    Get the block kind encoded in a `_..._block_init` helper name, or `None`.

    Args:
        name: A helper-call name.

    Returns:
        The kind for a recognized `_{kind}_block_init` (e.g. `stack`), or `None` when
        `name` is not such a helper or carries no usable kind (`_block_init`,
        `_unknown_block_init`).
    """
    match = _BLOCK_INIT_HELPER.match(name)
    if match is None:
        return None
    kind = match.group(1)
    return kind if kind not in (None, "unknown") else None


def get_isa(isa: cexpr_t) -> str | None:
    """Get the isa name from the isa expression"""
    if isa.op == ida_hexrays.cot_ref:
        inner = isa.x
        if inner.op == ida_hexrays.cot_obj:
            return memory.name_from_ea(inner.obj_ea)
    elif isa.op == ida_hexrays.cot_helper:
        return isa.helper
    return None


@dataclass
class BlockBaseFieldsAssignments:
    assignments: list[cinsn_t]
    ea: int | None
    type: tinfo_t | None
    isa: cexpr_t | None
    flags: cexpr_t | None
    reserved: cexpr_t | None
    invoke: cexpr_t | None
    descriptor: cexpr_t | None

    def __str__(self) -> str:
        return (
            f"isa: {self.isa.dstr() if self.isa else 'None'}, "
            f"flags: {self.flags.dstr() if self.flags else 'None'}, "
            f"reserved: {self.reserved.dstr() if self.reserved else 'None'}, "
            f"invoke: {self.invoke.dstr() if self.invoke else 'None'}, "
            f"descriptor: {self.descriptor.dstr() if self.descriptor else 'None'}"
        )

    @staticmethod
    def initial() -> "BlockBaseFieldsAssignments":
        return BlockBaseFieldsAssignments(assignments=[], isa=None, flags=None, reserved=None, invoke=None, descriptor=None, type=None, ea=None)

    def is_completed(self) -> bool:
        """Check if all base fields have been assigned"""
        return self.isa is not None and self.flags is not None and self.reserved is not None and self.invoke is not None and self.descriptor is not None

    def add_assignment(self, assignment: StructFieldAssignment) -> bool:
        """Add an assignment to the list of assignments"""
        if self.type is None:
            self.type = assignment.type

        field_name = assignment.member.name
        if field_name == "isa":
            self.isa = assignment.expr
            self.ea = assignment.insn.ea
        elif field_name == "flags":
            if assignment.is_cast_assign:
                # We need to split it to flags and reserved
                expr = assignment.expr
                if expr.op != ida_hexrays.cot_num:
                    print(f"[Error] invalid flags assignment. Expected const, got: {expr.dstr()}")
                    return False

                num_val = expr.numval()
                self.flags = cexpr.from_const_value(num_val & 0xFF_FF_FF_FF, is_hex=True)
                self.reserved = cexpr.from_const_value(num_val >> 32, is_hex=True)
            else:
                self.flags = assignment.expr
        elif field_name == "reserved":
            self.reserved = assignment.expr
        elif field_name == "invoke":
            self.invoke = assignment.expr
        elif field_name == "descriptor":
            self.descriptor = assignment.expr
        else:
            return False

        self.assignments.append(assignment.insn)
        return True
