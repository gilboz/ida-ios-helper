__all__ = [
    "swift_prolog_hook_component",
    "swift_types_component",
    "swift_types_hook_component",
]

from ioshelper.base.reloadable_plugin import HexraysHookComponent, StartupScriptComponent

from .prolog_rewrite import SwiftPrologRewriteHook
from .swift_types import SwiftClassCallHook, fix_swift_types

swift_types_component = StartupScriptComponent.factory(
    "swift-types", "Fix Swift types when the database is opened", [fix_swift_types]
)
swift_types_hook_component = HexraysHookComponent.factory(
    "swift-class-call", "Rewrite Swift class method calls in the decompiler", [SwiftClassCallHook]
)
swift_prolog_hook_component = HexraysHookComponent.factory(
    "swift-prolog-rewrite", "Hide Swift function prologs in the decompiler", [SwiftPrologRewriteHook]
)
