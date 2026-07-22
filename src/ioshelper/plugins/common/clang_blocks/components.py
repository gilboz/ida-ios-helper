"""Component wiring for the clang-blocks features; `core.py` registers these from the package root."""

__all__ = [
    "clang_block_optimizer_component",
    "clang_blocks_analyzer_component",
    "clang_blocks_auto_analyzer_component",
]

import ida_kernwin
import idaapi
from idahelper import functions

from ioshelper.base.reloadable_plugin import HexraysHookComponent, UIAction, UIActionsComponent

from .analyzer.auto_analyze import BlocksAutoAnalyzeHook
from .analyzer.options import CLANG_BLOCKS_ANALYZER_COMPONENT_NAME, BlocksAnalyzerOptions
from .analyzer.pipeline import analyze_blocks_in_func
from .optimizer import objc_blocks_optimizer_hooks_t

ACTION_ID = "ioshelper:analyze_clang_blocks"


def dynamic_menu_add(widget, _popup) -> bool:
    if ida_kernwin.get_widget_type(widget) != ida_kernwin.BWN_PSEUDOCODE:
        return False
    return functions.is_in_function(ida_kernwin.get_screen_ea())


# The manual action and the auto-analyze hook are separate components sharing the
# `clang-blocks-analyzer` name and options section, so to users they are one feature.
# The auto hook is gated by the section's `auto` option (off by default) via
# `BlocksAutoAnalyzeHook.build`.
clang_blocks_analyzer_component = UIActionsComponent.factory(
    CLANG_BLOCKS_ANALYZER_COMPONENT_NAME,
    "Analyze Clang blocks in the current function: __block byref args, capture field names and types, block names",
    [
        lambda core, options: UIAction(
            ACTION_ID,
            idaapi.action_desc_t(
                ACTION_ID,
                "[ios-helper] Analyze stack blocks in current function",
                ClangBlocksAnalyzeAction(options),
                "Alt+Shift+s",
            ),
            menu_location=UIAction.base_location(core),
            dynamic_menu_add=dynamic_menu_add,
        )
    ],
    options=BlocksAnalyzerOptions,
)

clang_blocks_auto_analyzer_component = HexraysHookComponent.factory(
    CLANG_BLOCKS_ANALYZER_COMPONENT_NAME,
    "Auto-run the block analysis the first time a function using blocks is decompiled",
    [BlocksAutoAnalyzeHook.build],
    options=BlocksAnalyzerOptions,
)

clang_block_optimizer_component = HexraysHookComponent.factory(
    "clang-blocks-optimizer",
    "Optimize Clang blocks initialization in the decompiler",
    [objc_blocks_optimizer_hooks_t],
)


class ClangBlocksAnalyzeAction(ida_kernwin.action_handler_t):
    """
    Run the block analysis pipeline on the current function.

    IDA's own stack-block analysis always runs first; the follow-up steps — byref
    argument recovery, capture field renaming/retyping, and block naming — are gated
    by `options`.

    Args:
        options: The `[clang-blocks-analyzer]` step gates, resolved by the component
            and passed in.
    """

    def __init__(self, options: BlocksAnalyzerOptions) -> None:
        super().__init__()
        self._options = options

    def activate(self, ctx: ida_kernwin.action_ctx_base_t):
        if ctx.cur_func is None:
            print("No function selected")
            return 0

        analyze_blocks_in_func(ctx.cur_func.start_ea, self._options)
        return 0

    def update(self, ctx) -> int:
        return idaapi.AST_ENABLE_ALWAYS
