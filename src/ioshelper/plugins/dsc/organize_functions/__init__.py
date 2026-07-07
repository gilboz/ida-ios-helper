__all__ = ["organize_functions_component"]

import ida_kernwin
from ida_kernwin import action_handler_t

from ioshelper.base.reloadable_plugin import UIAction, UIActionsComponent

from .organize_functions import organize_functions

ACTION_ID = "ioshelper:organize_dsc_functions"

organize_functions_component = UIActionsComponent.factory(
    "dsc-organize-functions",
    "Organize the Functions window into folders by module and segment kind (stubs, ...)",
    [
        lambda core: UIAction(
            ACTION_ID,
            ida_kernwin.action_desc_t(
                ACTION_ID,
                "Organize functions into folders by their segment",
                OrganizeFunctionsAction(),
            ),
            menu_location=UIAction.base_location(core),
        )
    ],
)


class OrganizeFunctionsAction(action_handler_t):
    def activate(self, ctx: ida_kernwin.action_ctx_base_t) -> int:
        stats = organize_functions()
        print(f"[iOSHelper] organized functions: {stats.moved} moved, {stats.skipped} skipped, {stats.failed} failed")
        return 1

    def update(self, ctx) -> int:
        return ida_kernwin.AST_ENABLE_ALWAYS
