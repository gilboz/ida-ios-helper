__all__ = ["OBJC_LVAR_RENAMER_COMPONENT_NAME", "objc_lvar_renamer_component"]

from ioshelper.base.reloadable_plugin import HexraysHookComponent

from .hook import ObjcLvarRenameHook

OBJC_LVAR_RENAMER_COMPONENT_NAME = "objc-lvar-renamer"

# One maturity hook running every name source; the sources themselves are gated
# individually inside the pipeline, by their own names (`objc-rename-args`,
# `objc-rename-getters`, `objc-rename-callee-args`) in the same
# `disabled_components` / `experimental_components` config lists as components.
objc_lvar_renamer_component = HexraysHookComponent.factory(
    OBJC_LVAR_RENAMER_COMPONENT_NAME,
    "Name default-named local variables from Obj-C selectors (args, getters, callee keyword args)",
    [ObjcLvarRenameHook],
)
