__all__ = [
    "mass_objc_arg_renamer_component",
    "objc_arg_renamer_component",
    "rename_all_objc_method_args",
    "rename_objc_method_args",
]

import ida_kernwin
import idaapi
from ida_kernwin import action_handler_t
from idahelper import widgets

from ioshelper.base.reloadable_plugin import UIAction, UIActionsComponent

from .renamer import rename_all_objc_method_args, rename_objc_method_args

LOCAL_ACTION_ID = "ioshelper:rename_objc_args"
MASS_ACTION_ID = "ioshelper:mass_rename_objc_args"


objc_arg_renamer_component = UIActionsComponent.factory(
    "objc-arg-renamer",
    "Rename Obj-C method arguments in the current function",
    [
        lambda core: UIAction(
            LOCAL_ACTION_ID,
            idaapi.action_desc_t(
                LOCAL_ACTION_ID,
                "Rename Obj-C method arguments in current function",
                RenameObjcArgsAction(),
                "F3",
            ),
            menu_location=UIAction.base_location(core),
        )
    ],
)

mass_objc_arg_renamer_component = UIActionsComponent.factory(
    "objc-arg-renamer-all",
    "Rename Obj-C method arguments in all functions",
    [
        lambda core: UIAction(
            MASS_ACTION_ID,
            idaapi.action_desc_t(
                MASS_ACTION_ID,
                "Rename Obj-C method arguments in all functions",
                RenameAllObjcArgsAction(),
            ),
            menu_location=UIAction.base_location(core),
        )
    ],
)


class RenameObjcArgsAction(action_handler_t):
    def activate(self, ctx: ida_kernwin.action_ctx_base_t) -> int:
        if ctx.cur_func is None:
            print("[Error] Not inside a function")
            return 0

        if rename_objc_method_args(ctx.cur_func) and ctx.widget is not None:
            widgets.refresh_widget(ctx.widget)
        return 0

    def update(self, ctx) -> int:
        return idaapi.AST_ENABLE_ALWAYS


class RenameAllObjcArgsAction(action_handler_t):
    def activate(self, ctx: ida_kernwin.action_ctx_base_t) -> int:
        rename_all_objc_method_args()
        return 0

    def update(self, ctx) -> int:
        return idaapi.AST_ENABLE_ALWAYS
