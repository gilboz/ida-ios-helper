__all__ = ["swift_oslog_hook_component"]

from ioshelper.base.reloadable_plugin import HexraysHookComponent

from .log_hook import SwiftLogRewriteHook

swift_oslog_hook_component = HexraysHookComponent.factory(
    "swift-oslog", "Rewrite Swift os_log calls in the decompiler", [SwiftLogRewriteHook]
)
