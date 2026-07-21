"""
The renamer's config schema: the `[objc-lvar-renamer]` section of `ioshelper.cfg`, one
boolean gate per name source.
"""

__all__ = [
    "OBJC_LVAR_RENAMER_COMPONENT_NAME",
    "RenamerOptions",
]

import dataclasses

from ioshelper.base.config import ComponentOptions

OBJC_LVAR_RENAMER_COMPONENT_NAME = "objc-lvar-renamer"


@dataclasses.dataclass(frozen=True)
class RenamerOptions(ComponentOptions, section=OBJC_LVAR_RENAMER_COMPONENT_NAME):
    """
    The `[objc-lvar-renamer]` config section: one boolean gate per name source.

    Attributes:
        args: Whether the `args` source (the function's own selector) runs.
        getters: Whether the work-in-progress `getters` source runs.
        callee_args: Whether the work-in-progress `callee-args` source runs.
    """

    args: bool = True
    getters: bool = False
    callee_args: bool = False

    def __bool__(self) -> bool:
        """Whether at least one source is enabled."""
        return self.args or self.getters or self.callee_args

    def log(self) -> None:
        """Log each source's enabled/disabled state."""
        states = ((f.name.replace("_", "-"), getattr(self, f.name)) for f in dataclasses.fields(self))
        summary = ", ".join(f"{name}: {'enabled' if enabled else 'disabled'}" for name, enabled in states)
        print(f"[{OBJC_LVAR_RENAMER_COMPONENT_NAME}] name sources: {summary}")
