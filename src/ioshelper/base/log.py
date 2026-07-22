"""
Debug logging for the plugin.

`debug` prints a `[Debug]`-prefixed line only when debug mode is enabled in the config
(`debug = true` in `ioshelper.cfg`), so debug output is a single, uniformly gated call
site instead of an `if config.debug: print(...)` scattered at each caller. Callers add
their own component prefix to the message (`debug(f"{COMPONENT_NAME}: ...")`).
"""

__all__ = ["debug"]

from ioshelper.base.config import config


def debug(message: str) -> None:
    """
    Print `message` prefixed with `[Debug]`, only when debug mode is enabled.

    Args:
        message: The line to print; callers prepend their own component prefix.
    """
    if config.debug:
        print(f"[Debug] {message}")
