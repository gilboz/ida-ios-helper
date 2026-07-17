__all__ = [
    "auto_objc_arg_renamer_component",
    "mass_objc_arg_renamer_component",
    "objc_arg_renamer_component",
    "rename_all_objc_method_args",
    "rename_objc_method_args",
]

import ida_kernwin
import idaapi
from ida_kernwin import action_handler_t
from idahelper import functions, memory, objc

from ioshelper.base.reloadable_plugin import HexraysHookComponent, UIAction, UIActionsComponent

from .hook import ObjcArgRenameHook
from .renamer import rename_all_objc_method_args, rename_objc_method_args

LOCAL_ACTION_ID = "ioshelper:rename_objc_args"
MASS_ACTION_ID = "ioshelper:mass_rename_objc_args"


def dynamic_menu_add(widget, _popup) -> bool:
    if ida_kernwin.get_widget_type(widget) != ida_kernwin.BWN_PSEUDOCODE:
        return False
    func_ea = functions.get_start_of_function(ida_kernwin.get_screen_ea())
    if func_ea is None:
        return False
    name = memory.name_from_ea(func_ea)
    return name is not None and objc.is_objc_method(name)


objc_arg_renamer_component = UIActionsComponent.factory(
    "objc-arg-renamer",
    "Rename Obj-C method arguments in the current function",
    [
        lambda core: UIAction(
            LOCAL_ACTION_ID,
            idaapi.action_desc_t(
                LOCAL_ACTION_ID,
                "[ios-helper] Obj-C: rename argument names by selector",
                RenameObjcArgsAction(),
                "F3",
            ),
            menu_location=UIAction.base_location(core),
            dynamic_menu_add=dynamic_menu_add,
        )
    ],
)

auto_objc_arg_renamer_component = HexraysHookComponent.factory(
    "objc-arg-renamer-auto",
    "Rename Obj-C method arguments automatically on decompilation",
    [ObjcArgRenameHook],
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

        # No explicit refresh: renaming through the focused pseudocode view refreshes it in place
        rename_objc_method_args(ctx.cur_func)
        return 0

    def update(self, ctx) -> int:
        return idaapi.AST_ENABLE_ALWAYS


class RenameAllObjcArgsAction(action_handler_t):
    def activate(self, ctx: ida_kernwin.action_ctx_base_t) -> int:
        rename_all_objc_method_args()
        return 0

    def update(self, ctx) -> int:
        return idaapi.AST_ENABLE_ALWAYS
