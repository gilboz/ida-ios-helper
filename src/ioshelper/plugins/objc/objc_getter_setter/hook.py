"""
Run the getter/setter local renamer automatically on every decompilation.

A `Hexrays_Hooks.maturity` hook gated on `CMAT_FINAL` so it runs exactly once per real
decompilation, when the ctree is complete and the lvars already carry the saved user
settings. Writes go through `perform_lvar_modifications_during_decompilation` (saved-settings
writes plus patching the in-flight `lvar_t`s), costing zero extra decompilations; the next
decompilation applies the saved names natively and the hook no-ops.
"""

__all__ = ["ObjcGetterSetterRenameHook"]

import ida_hexrays
from ida_hexrays import Hexrays_Hooks, cfunc_t

from .renamer import rename_getters_setters_during_decompilation


class ObjcGetterSetterRenameHook(Hexrays_Hooks):
    def maturity(self, cfunc: cfunc_t, new_maturity: int) -> int:
        if new_maturity == ida_hexrays.CMAT_FINAL:
            rename_getters_setters_during_decompilation(cfunc)
        return 0
