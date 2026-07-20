__all__ = ["OBJC_GETTER_SETTER_COMPONENT_NAME", "objc_getter_setter_renamer_component"]

from ioshelper.base.reloadable_plugin import HexraysHookComponent

from .hook import ObjcGetterSetterRenameHook

# WIP: naming locals from getter/setter selectors is new and not yet well tested, so this
# component is experimental and disabled by default. Opt in by adding this name to
# `experimental_components` in the config.
OBJC_GETTER_SETTER_COMPONENT_NAME = "objc-getter-setter-renamer"

objc_getter_setter_renamer_component = HexraysHookComponent.factory(
    OBJC_GETTER_SETTER_COMPONENT_NAME,
    "Name local variables from the Obj-C getter/setter they come from (experimental)",
    [ObjcGetterSetterRenameHook],
)
