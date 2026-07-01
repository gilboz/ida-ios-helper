__all__ = ["dump_ps_component"]

import ida_hexrays
import ida_kernwin
import idaapi
from ida_kernwin import action_handler_t

from ioshelper.base.reloadable_plugin import UIAction, UIActionsComponent

from .dump_pseudocode import dump_ps

ACTION_ID = "ioshelper:dump_debug_pseudocode"
SHORTCUT = "F3"  # pick something unused; see below

dump_ps_component = UIActionsComponent.factory(
    "Dump annotated pseudocode (debug)",
    [
        lambda core: UIAction(
            ACTION_ID,
            idaapi.action_desc_t(
                ACTION_ID,
                "Dump annotated pseudocode to /tmp/pseudocode.txt",
                DumpPseudocodeAction(),
                SHORTCUT,
            ),
            menu_location=UIAction.base_location(core),
        )
    ],
)


class DumpPseudocodeAction(action_handler_t):
    def activate(self, ctx: ida_kernwin.action_ctx_base_t) -> int:
        ea = ctx.cur_ea if ctx.cur_func else None
        try:
            dump_ps(ea=ea)
        except RuntimeError as exc:
            print(f"[ioshelper] {exc}")
            return 0
        return 0

    def update(self, ctx: ida_kernwin.action_ctx_base_t) -> int:
        if not ida_hexrays.init_hexrays_plugin():
            return idaapi.AST_DISABLE
        return idaapi.AST_ENABLE
