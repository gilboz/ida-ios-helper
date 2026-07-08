__all__ = [
    "clang_block_args_analyzer_component",
    "clang_block_optimizer_component",
    "run_objc_plugin_on_func",
    "try_add_block_arg_byref_to_func",
]

import ida_kernwin
import idaapi
from idahelper import functions, widgets

from ioshelper.base.reloadable_plugin import HexraysHookComponent, UIAction, UIActionsComponent

from .analyze_byref_args import try_add_block_arg_byref_to_func
from .optimize_blocks_init import objc_blocks_optimizer_hooks_t
from .utils import run_objc_plugin_on_func

ACTION_ID = "ioshelper:restore_llvm_block_args_byref"


def dynamic_menu_add(widget, _popup) -> bool:
    if ida_kernwin.get_widget_type(widget) != ida_kernwin.BWN_PSEUDOCODE:
        return False
    return functions.is_in_function(ida_kernwin.get_screen_ea())


clang_block_args_analyzer_component = UIActionsComponent.factory(
    "clang-blocks-args",
    "Analyze stack-allocated Clang blocks and their __block arguments",
    [
        lambda core: UIAction(
            ACTION_ID,
            idaapi.action_desc_t(
                ACTION_ID,
                "[ios-helper] Analyze stack blocks in current function",
                ClangBlockDetectByrefAction(),
                "Alt+Shift+s",
            ),
            menu_location=UIAction.base_location(core),
            dynamic_menu_add=dynamic_menu_add,
        )
    ],
)

clang_block_optimizer_component = HexraysHookComponent.factory(
    "clang-blocks-optimizer",
    "Optimize Clang blocks initialization in the decompiler",
    [objc_blocks_optimizer_hooks_t],
)


class ClangBlockDetectByrefAction(ida_kernwin.action_handler_t):
    def activate(self, ctx: ida_kernwin.action_ctx_base_t):
        if ctx.cur_func is None:
            print("No function selected")
            return 0

        run_objc_plugin_on_func(ctx.cur_ea)
        widgets.refresh_pseudocode_widgets()
        if try_add_block_arg_byref_to_func(ctx.cur_func.start_ea):
            widgets.refresh_pseudocode_widgets()
        return 0

    def update(self, ctx) -> int:
        return idaapi.AST_ENABLE_ALWAYS
