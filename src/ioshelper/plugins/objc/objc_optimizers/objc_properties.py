__all__ = ["objc_properties_optimizer_t"]

import ida_hexrays
from ida_hexrays import mcallinfo_t, minsn_t, mop_t
from idahelper.microcode import mop, mreg

from ._base import CallInsnVisitor, CallMopVisitor, CallOptimizer
from ._match import match_func_name

# Replace assign(&x, y) with x = y;
ASSIGN_FUNCTIONS: list[str] = [
    "objc_storeStrong",
]

# Replace set(x, offset, value) with x.field = value;
SET_PROPERTY_FUNCTIONS: list[str] = [
    "objc_setProperty_atomic_copy",
    "objc_setProperty_nonatomic_copy",
]

# Replace get(x, offset) with x.field;
GET_PROPERTY_FUNCTIONS: list[str] = [
    "objc_getProperty",
]


class _PropertiesMopVisitor(CallMopVisitor):
    def handle_call(self, op: mop_t, insn: minsn_t, name: str) -> None:
        if not match_func_name(GET_PROPERTY_FUNCTIONS, name):
            return

        fi: mcallinfo_t = insn.d.f
        if fi.args.empty():
            # No arguments, probably IDA have not optimized it yet
            return

        offset = mop.get_const_int(fi.args[2])
        if offset is None:
            # Offset is not const so cannot optimize
            return

        # Replace the call with a field access
        field_access = create_field_access(fi.args[0], offset, self.curins.ea, insn.d.size)
        # Swap mop containing call with field access
        op.d.swap(field_access)
        self.count()


class _PropertiesInsnVisitor(CallInsnVisitor):
    def handle_call(self, insn: minsn_t, name: str) -> None:
        if match_func_name(ASSIGN_FUNCTIONS, name):
            self._assign(insn)
        elif match_func_name(SET_PROPERTY_FUNCTIONS, name):
            self._set_property(insn)

    def _assign(self, insn: minsn_t) -> None:
        fi: mcallinfo_t = insn.d.f
        if fi.args.size() != 2:
            # Not enough argument, probably not optimized yet
            return

        insn.opcode = ida_hexrays.m_stx
        # src
        insn.l.swap(fi.args[1])
        # dest
        insn.d.swap(fi.args[0])
        # seg - need to be CS/DS according to the docs.
        insn.r.make_reg(mreg.cs_reg(), 2)
        self.count()

    def _set_property(self, insn: minsn_t) -> None:
        fi: mcallinfo_t = insn.d.f
        if fi.args.size() != 4:
            # Not enough argument, probably not optimized yet
            return

        offset = mop.get_const_int(fi.args[3])
        if offset is None:
            # Offset is not constant
            return

        insn.opcode = ida_hexrays.m_stx
        # src
        insn.l.swap(fi.args[2])
        # dest
        insn.d.swap(create_base_plus_offset(fi.args[0], offset, self.curins.ea))
        # seg - need to be CS/DS according to the docs.
        insn.r.make_reg(mreg.cs_reg(), 2)
        self.count()


class objc_properties_optimizer_t(CallOptimizer):
    """Lower Obj-C property accessors (storeStrong, get/setProperty) into direct field loads/stores."""

    mop_visitor_cls = _PropertiesMopVisitor
    insn_visitor_cls = _PropertiesInsnVisitor


def create_field_access(base: mop_t, offset: int, ea: int, op_size: int) -> minsn_t:
    # Create a new mop for the field access

    base_plus_offset = create_base_plus_offset(base, offset, ea)

    # ldx := *(add_wrapper)
    ldx = minsn_t(ea)
    ldx.opcode = ida_hexrays.m_ldx
    ldx.l.make_reg(mreg.cs_reg(), 2)
    ldx.r = base_plus_offset
    ldx.d = mop_t()
    ldx.d.size = op_size
    ldx.size = op_size
    return ldx


def create_base_plus_offset(base: mop_t, offset: int, ea: int) -> mop_t:
    # add := minsn_t(base + offset)
    add = minsn_t(ea)
    add.opcode = ida_hexrays.m_add
    add.l.swap(mop_t(base))
    add.r.make_number(offset, 8)
    add.d = mop_t()
    add.d.size = 8
    add.size = 8

    # add_wrapper := mop_t(add)
    add_wrapper = mop_t()
    add_wrapper.create_from_insn(add)
    add_wrapper.size = 8
    return add_wrapper
