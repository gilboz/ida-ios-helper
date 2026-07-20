"""
Run the Obj-C lvar renaming pipeline automatically on every decompilation.

A `Hexrays_Hooks.maturity` hook gated on `CMAT_FINAL` so it runs exactly once per real
decompilation, when the ctree is complete and the lvars already carry the saved user
settings — variables still holding their default `aN`/`vN` name are exactly the
safely-renamable ones. The writes go through `perform_lvar_modifications_during_decompilation`
(saved-settings writes plus patching the in-flight `lvar_t`s), costing zero extra
decompilations; the next decompilation applies the saved names natively and the hook no-ops.
"""

__all__ = ["ObjcLvarRenameHook"]

import ida_hexrays
from ida_hexrays import Hexrays_Hooks, cfunc_t

from .pipeline import rename_objc_lvars_during_decompilation


class ObjcLvarRenameHook(Hexrays_Hooks):
    def maturity(self, cfunc: cfunc_t, new_maturity: int) -> int:
        if new_maturity == ida_hexrays.CMAT_FINAL:
            rename_objc_lvars_during_decompilation(cfunc)
        return 0
