__all__ = ["report_stub_modules_component"]

import ida_kernwin
from ida_kernwin import action_handler_t

from ioshelper.base.reloadable_plugin import UIAction, UIActionsComponent

from .reporter import report_modules_to_load

ACTION_ID = "ioshelper:report_stub_modules"

# The right-click entry is only meaningful over code, where a function is under the cursor.
_CODE_WIDGETS: frozenset[int] = frozenset({ida_kernwin.BWN_PSEUDOCODE, ida_kernwin.BWN_DISASM})


def _add_to_code_popup(widget: "ida_kernwin.TWidget *", popup: "ida_kernwin.TPopupMenu *") -> bool:  # noqa: F722
    """Attach the action to the right-click menu of pseudocode and disassembly views only."""
    return ida_kernwin.get_widget_type(widget) in _CODE_WIDGETS


report_stub_modules_component = UIActionsComponent.factory(
    "dsc-stub-modules",
    "Report the dyld_shared_cache modules to load so the current function's stub calls resolve",
    [
        lambda core: UIAction(
            ACTION_ID,
            ida_kernwin.action_desc_t(
                ACTION_ID,
                "Report modules to load for this function's stubs",
                ReportStubModulesActionHandler(),
            ),
            menu_location=UIAction.base_location(core),
            dynamic_menu_add=_add_to_code_popup,
        )
    ],
)


class ReportStubModulesActionHandler(action_handler_t):
    def activate(self, ctx: ida_kernwin.action_ctx_base_t) -> int:
        report_modules_to_load(ida_kernwin.get_screen_ea())
        return 1

    def update(self, ctx) -> int:
        return ida_kernwin.AST_ENABLE_ALWAYS
