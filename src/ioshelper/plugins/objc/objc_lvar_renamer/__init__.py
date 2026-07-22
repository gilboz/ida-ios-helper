__all__ = ["OBJC_LVAR_RENAMER_COMPONENT_NAME", "objc_lvar_renamer_component"]

from ioshelper.base.reloadable_plugin import HexraysHookComponent

from .options import OBJC_LVAR_RENAMER_COMPONENT_NAME, RenamerOptions
from .renamer import ObjcLvarRenameHook

# One maturity hook running every name source; the sources themselves are configured
# as booleans (`args`, `getters`, `callee-args`) in the component's own
# `[objc-lvar-renamer]` section of `ioshelper.cfg`, resolved when this component loads.
objc_lvar_renamer_component = HexraysHookComponent.factory(
    OBJC_LVAR_RENAMER_COMPONENT_NAME,
    "Name default-named local variables from Obj-C selectors (args, getters, callee keyword args)",
    [ObjcLvarRenameHook],
    options=RenamerOptions,
)
