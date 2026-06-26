__all__ = ["objc_calls_optimizer_t"]

import re

import ida_hexrays
from ida_hexrays import mblock_t, mcallinfo_t, minsn_t, minsn_visitor_t, mop_t, mop_visitor_t
from idahelper.microcode import minsn, mop, mreg

from ioshelper.base.utils import CounterMixin, match

PREFIXES_TO_IGNORE: list[str] = [
    "_",
    "__",
    "j_",
    "j__",
]

_SORTED_PREFIXES = sorted(PREFIXES_TO_IGNORE, key=len, reverse=True)

_SUFFIXES_TO_IGNORE: list[str | re.Pattern] = [
    re.compile(r"_x\d{1,2}$"),
    re.compile(r"_\d+$"),
]


def match_func_name(arr: list[str | re.Pattern], name: str) -> bool:
    for prefix in _SORTED_PREFIXES:
        if name.startswith(prefix):
            name = name[len(prefix) :]
            break
    for suffix in _SUFFIXES_TO_IGNORE:
        if isinstance(suffix, str):
            if name.endswith(suffix):
                name = name[: -len(suffix)]
                break
        else:
            m = suffix.search(name)
            if m is not None and m.end() == len(name):
                name = name[: m.start()]
                break

    return match(arr, name)


# Replace f(x) with x
ID_FUNCTIONS_TO_REPLACE_WITH_ARG: list[str | re.Pattern] = [
    "objc_retain",
    "objc_retainAutorelease",
    "objc_autoreleaseReturnValue",
    "objc_autorelease",
    "objc_claimAutoreleasedReturnValue",
    "objc_retainBlock",
    "objc_unsafeClaimAutoreleasedReturnValue",
    "objc_retainAutoreleasedReturnValue",
    "swift_bridgeObjectRetain",
]

# Remove f(x) calls
VOID_FUNCTIONS_TO_REMOVE_WITH_SINGLE_ARG: list[str | re.Pattern] = [
    # Objective-C
    "objc_release",
    # intrinsics
    "break",
    # swift
    "swift_bridgeObjectRelease",
]

VOID_FUNCTION_TO_REMOVE_WITH_MULTIPLE_ARGS: list[str | re.Pattern] = [
    # Blocks
    "Block_object_dispose",
]

# Replace assign(&x, y) with x = y;
ASSIGN_FUNCTIONS: list[str | re.Pattern] = [
    "objc_storeStrong",
]

SET_PROPERTY_FUNCTIONS: list[str | re.Pattern] = [
    "objc_setProperty_atomic_copy",
    "objc_setProperty_nonatomic_copy",
]

# Replace get(x, offset) with x.field;
GET_PROPERTY_FUNCTIONS: list[str | re.Pattern] = [
    "objc_getProperty",
]


class mop_optimizer_t(mop_visitor_t, CounterMixin):
    def visit_mop(self, op: mop_t, tp, is_target: bool) -> int:
        # No assignment dest, we want a call instruction
        if not is_target and op.d is not None:
            self.visit_instruction_mop(op)
        return 0

    def visit_instruction_mop(self, op: mop_t):
        # We only want calls
        insn: minsn_t = op.d
        if insn.opcode != ida_hexrays.m_call:
            return

        # Calls with names
        name = minsn.get_func_name_of_call(insn)
        if name is None:
            print(f'[Error] No name for {insn.dstr()}')
            return

        # If it should be optimized to first arg, optimize
        if match_func_name(ID_FUNCTIONS_TO_REPLACE_WITH_ARG, name):
            fi: mcallinfo_t = insn.d.f
            if fi.args.empty():
                print(f'[Error] No arguments for {name}')
                # No arguments, probably IDA have not optimized it yet
                return

            # Swap mop containing call with arg0
            op.swap(fi.args[0])
            self.count()

        # If it should be optimized to field access, optimize
        elif match_func_name(GET_PROPERTY_FUNCTIONS, name):
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


class insn_optimizer_t(minsn_visitor_t, CounterMixin):
    def visit_minsn(self) -> int:
        # We only want calls
        insn: minsn_t = self.curins
        if insn.opcode == ida_hexrays.m_call:
            self.visit_call_insn(insn, self.blk)
        return 0

    def visit_call_insn(self, insn: minsn_t, blk: mblock_t):
        # Calls with names
        name = minsn.get_func_name_of_call(insn)
        if name is None:
            return

        for optimization in [
            self.void_function_to_remove,
            self.id_function_to_replace_with_their_arg,
            self.assign_functions,
            self.set_property_functions,
        ]:
            # noinspection PyArgumentList
            if optimization(name, insn, blk):
                return

    def try_remove_call(
        self,
        insn: minsn_t,
        *,
        name: str,
        exact_arg_count: int | None = 1,
        require_void_return: bool = False,
        require_discarded_return: bool = False,
    ) -> bool:
        """
        Nop a call instruction when argument and return-value preconditions are satisfied.
        """
        fi: mcallinfo_t = insn.d.f

        if fi.args.empty():
            return False

        if exact_arg_count is not None and len(fi.args) != exact_arg_count:
            return False

        if any(arg.has_side_effects() for arg in fi.args):
            print("[Error] arguments with side effects are not supported yet!")
            return False

        if require_void_return and (not fi.return_type or not fi.return_type.is_void()):
            print(
                f"[Error] Cannot remove {name} as this is an embedded instruction. "
                "Is the return type correct? it should be void."
            )
            return False

        if require_discarded_return and not fi.retregs.empty():
            return False

        self.blk.make_nop(insn)
        self.count()
        return True

    def void_function_to_remove(self, name: str, insn: minsn_t, blk: mblock_t) -> bool:
        if match_func_name(VOID_FUNCTIONS_TO_REMOVE_WITH_SINGLE_ARG, name):
            exact_arg_count = 1
        elif match_func_name(VOID_FUNCTION_TO_REMOVE_WITH_MULTIPLE_ARGS, name):
            exact_arg_count = None
        else:
            return False

        return self.try_remove_call(
            insn,
            name=name,
            exact_arg_count=exact_arg_count,
            require_void_return=True,
        )

    def id_function_to_replace_with_their_arg(self, name: str, insn: minsn_t, blk: mblock_t) -> bool:
        if not match_func_name(ID_FUNCTIONS_TO_REPLACE_WITH_ARG, name):
            return False

        # Might be a call with destination (for example, if it is the last statement in the function)
        # Statement-level retain with a discarded return — remove entirely when safe.
        if self.try_remove_call(insn, name=name, exact_arg_count=1, require_discarded_return=True):
            return True

        # Make instruction mov instead of call
        insn.opcode = ida_hexrays.m_mov
        fi: mcallinfo_t = insn.d.f

        # We cannot replace function with their arg if there is no args or no return registers
        if fi.args.empty() or fi.retregs.empty():
            return False
        insn.l.swap(fi.args[0])
        insn.d.swap(fi.retregs[0])
        self.count()
        return True

    def assign_functions(self, name: str, insn: minsn_t, _blk: mblock_t) -> bool:
        if not match_func_name(ASSIGN_FUNCTIONS, name):
            return False

        fi: mcallinfo_t = insn.d.f
        if fi.args.size() != 2:
            # Not enough argument, probably not optimized yet
            return False
        insn.opcode = ida_hexrays.m_stx
        # src
        insn.l.swap(fi.args[1])
        # dest
        insn.d.swap(fi.args[0])
        # seg - need to be CS/DS according to the docs.
        insn.r.make_reg(mreg.cs_reg(), 2)
        self.count()
        return True

    def set_property_functions(self, name: str, insn: minsn_t, _blk: mblock_t) -> bool:
        if not match_func_name(SET_PROPERTY_FUNCTIONS, name):
            return False

        fi: mcallinfo_t = insn.d.f
        if fi.args.size() != 4:
            # Not enough argument, probably not optimized yet
            return False

        offset = mop.get_const_int(fi.args[3])
        if offset is None:
            # Offset is not constant
            return False

        insn.opcode = ida_hexrays.m_stx
        # src
        insn.l.swap(fi.args[2])
        # dest
        insn.d.swap(create_base_plus_offset(fi.args[0], offset, self.curins.ea))
        # seg - need to be CS/DS according to the docs.
        insn.r.make_reg(mreg.cs_reg(), 2)
        self.count()
        return True


class objc_calls_optimizer_t(ida_hexrays.optinsn_t):
    def func(self, blk: mblock_t, ins: minsn_t, optflags: int):
        # Let IDA reconstruct the calls before
        if blk.mba.maturity < ida_hexrays.MMAT_CALLS:
            return 0

        mop_optimizer = mop_optimizer_t(blk.mba, blk)
        insn_optimizer = insn_optimizer_t(blk.mba, blk)
        ins.for_all_ops(mop_optimizer)
        ins.for_all_insns(insn_optimizer)
        changes = mop_optimizer.cnt + insn_optimizer.cnt
        if changes:
            blk.mark_lists_dirty()
        return changes


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
