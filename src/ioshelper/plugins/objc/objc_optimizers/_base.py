__all__ = ["CallInsnVisitor", "CallMopVisitor", "CallOptimizer"]

import ida_hexrays
from ida_hexrays import mblock_t, mcallinfo_t, minsn_t, minsn_visitor_t, mop_t, mop_visitor_t
from idahelper.microcode import minsn

from ioshelper.base.utils import CounterMixin


class CallMopVisitor(mop_visitor_t, CounterMixin):
    """
    Visit named calls that appear as a value-producing operand (a call nested inside an expression).

    Subclasses implement `handle_call` to rewrite the operand in place.
    """

    def visit_mop(self, op: mop_t, tp, is_target: bool) -> int:
        # A call used as a value: not an assignment target, and the mop wraps an instruction.
        if not is_target and op.d is not None:
            insn: minsn_t = op.d
            if insn.opcode == ida_hexrays.m_call:
                name = minsn.get_func_name_of_call(insn)
                if name is not None:
                    self.handle_call(op, insn, name)
        return 0

    def handle_call(self, op: mop_t, insn: minsn_t, name: str) -> None:
        """Rewrite the call `insn` (wrapped by operand `op`) named `name`. Implemented by subclasses."""
        raise NotImplementedError

    def replace_with_first_arg(self, op: mop_t, insn: minsn_t, name: str) -> bool:
        """Replace `f(x)` used as a value with its first argument `x`."""
        fi: mcallinfo_t = insn.d.f
        if fi.args.empty():
            # No arguments, probably IDA have not optimized it yet
            print(f"[Error] No arguments for {name}")
            return False

        op.swap(fi.args[0])
        self.count()
        return True


class CallInsnVisitor(minsn_visitor_t, CounterMixin):
    """
    Visit named call instructions at statement level.

    Subclasses implement `handle_call` to rewrite or remove the call in place.
    """

    def visit_minsn(self) -> int:
        insn: minsn_t = self.curins
        if insn.opcode == ida_hexrays.m_call:
            name = minsn.get_func_name_of_call(insn)
            if name is not None:
                self.handle_call(insn, name)
        return 0

    def handle_call(self, insn: minsn_t, name: str) -> None:
        """Rewrite the statement-level call `insn` named `name`. Implemented by subclasses."""
        raise NotImplementedError

    def try_remove_call(
        self,
        insn: minsn_t,
        *,
        name: str,
        exact_arg_count: int | None = 1,
        require_void_return: bool = False,
        require_discarded_return: bool = False,
    ) -> bool:
        """Nop a call instruction when argument and return-value preconditions are satisfied."""
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

    def replace_with_first_arg(self, insn: minsn_t, name: str) -> bool:
        """Replace a statement-level `f(x)` with `x` (or remove it when its result is discarded)."""
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


class CallOptimizer(ida_hexrays.optinsn_t):
    """
    An `optinsn_t` that runs a mop-level and/or insn-level call visitor once IDA has reconstructed calls.

    Attributes:
        mop_visitor_cls: Visitor for calls nested as value operands, or `None` to skip that pass.
        insn_visitor_cls: Visitor for statement-level calls, or `None` to skip that pass.
    """

    mop_visitor_cls: type[CallMopVisitor] | None = None
    insn_visitor_cls: type[CallInsnVisitor] | None = None

    def func(self, blk: mblock_t, ins: minsn_t, optflags: int) -> int:
        # Let IDA reconstruct the calls before
        if blk.mba.maturity < ida_hexrays.MMAT_CALLS:
            return 0

        changes = 0
        if self.mop_visitor_cls is not None:
            mop_optimizer = self.mop_visitor_cls(blk.mba, blk)
            ins.for_all_ops(mop_optimizer)
            changes += mop_optimizer.cnt
        if self.insn_visitor_cls is not None:
            insn_optimizer = self.insn_visitor_cls(blk.mba, blk)
            ins.for_all_insns(insn_optimizer)
            changes += insn_optimizer.cnt

        if changes:
            blk.mark_lists_dirty()
        return changes
