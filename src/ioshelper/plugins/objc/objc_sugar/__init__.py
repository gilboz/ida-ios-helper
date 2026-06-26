__all__ = ["objc_sugar_component"]

from ioshelper.base.reloadable_plugin import HexraysHookComponent

from .objc_msgsend import objc_msgsend_hexrays_hooks_t
from .objc_sugar import objc_selector_hexrays_hooks_t

# Both passes are pseudocode-output syntactic sugar for Obj-C, so they ship as a
# single component. objc_msgsend is listed first so it installs first and thus
# fires *last* (Hexrays hooks fire in reverse install order): its msgSend rewrite
# and line-merge then run on text the selector pass has already shortened.
objc_sugar_component = HexraysHookComponent.factory(
    "ObjcSugar", [objc_msgsend_hexrays_hooks_t, objc_selector_hexrays_hooks_t]
)
