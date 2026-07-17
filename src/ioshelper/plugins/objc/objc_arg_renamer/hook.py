"""
Run the selector-based argument renamer automatically on every decompilation.

A `Hexrays_Hooks.maturity` hook, gated on `CMAT_FINAL` so it runs exactly once per real
decompilation. At that point the argument lvars are allocated and already carry the saved
user settings, so arguments still holding their default `aN` name are exactly the
safely-renamable ones — user renames are never clobbered. The writes go through
`perform_lvar_modifications_during_decompilation` (saved-settings writes plus patching
the in-flight `lvar_t`s), costing zero extra decompilations; the next decompilation
applies the saved names natively, leaves no `aN` arguments, and the hook no-ops.
"""

__all__ = ["ObjcArgRenameHook"]

import ida_hexrays
from ida_hexrays import Hexrays_Hooks, cfunc_t

from .renamer import rename_objc_method_args_during_decompilation


class ObjcArgRenameHook(Hexrays_Hooks):
    def maturity(self, cfunc: cfunc_t, new_maturity: int) -> int:
        if new_maturity == ida_hexrays.CMAT_FINAL:
            rename_objc_method_args_during_decompilation(cfunc)
        return 0
