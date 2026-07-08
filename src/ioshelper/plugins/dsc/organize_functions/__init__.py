__all__ = ["organize_functions_component"]

import ida_kernwin
from ida_kernwin import action_handler_t

from ioshelper.base.reloadable_plugin import UIAction, UIActionsComponent

from .organize_functions import organize_functions

ACTION_ID_NEW = "ioshelper:organize_dsc_functions"
ACTION_ID_ALL = "ioshelper:organize_dsc_functions_all"

organize_functions_component = UIActionsComponent.factory(
    "dsc-organize-functions",
    "Organize the Functions window into folders by module and segment kind (stubs, ...)",
    [
        lambda core: UIAction(
            ACTION_ID_NEW,
            ida_kernwin.action_desc_t(
                ACTION_ID_NEW,
                "Organize new functions into folders (root only)",
                OrganizeNewFunctionsAction(),
            ),
            menu_location=UIAction.base_location(core),
        ),
        lambda core: UIAction(
            ACTION_ID_ALL,
            ida_kernwin.action_desc_t(
                ACTION_ID_ALL,
                "Reorganize all functions into folders",
                OrganizeAllFunctionsAction(),
            ),
            menu_location=UIAction.base_location(core),
        ),
    ],
)


class OrganizeNewFunctionsAction(action_handler_t):
    """Differential pass: only functions still at the tree root (e.g. a freshly loaded dylib)."""

    def activate(self, ctx: ida_kernwin.action_ctx_base_t) -> int:
        stats = organize_functions(only_root=True)
        print(f"[iOSHelper] organized functions: {stats.moved} moved, {stats.skipped} skipped, {stats.failed} failed")
        return 1

    def update(self, ctx) -> int:
        return ida_kernwin.AST_ENABLE_ALWAYS


class OrganizeAllFunctionsAction(action_handler_t):
    """Full pass: move every function to its computed folder, wherever it currently is."""

    def activate(self, ctx: ida_kernwin.action_ctx_base_t) -> int:
        stats = organize_functions(only_root=False)
        print(f"[iOSHelper] organized functions: {stats.moved} moved, {stats.skipped} skipped, {stats.failed} failed")
        return 1

    def update(self, ctx) -> int:
        return ida_kernwin.AST_ENABLE_ALWAYS
