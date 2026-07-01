__all__ = ["OBJC_MSGSEND_ARGCOUNT_COMPONENT_NAME", "objc_msgsend_argcount_component"]

from ioshelper.base.reloadable_plugin import OptimizersComponent

from .optimizer import objc_msgsend_argcount_optimizer_t

# WIP: deriving the objc_msgSend argument count from the selector still mis-handles some
# calls, so this component is experimental and disabled by default. Opt in by adding this
# name to `experimental_components` in the config. Kept wired up for reference/dev.
OBJC_MSGSEND_ARGCOUNT_COMPONENT_NAME = "Obj-C msgSend arg count"

objc_msgsend_argcount_component = OptimizersComponent.factory(
    OBJC_MSGSEND_ARGCOUNT_COMPONENT_NAME, [objc_msgsend_argcount_optimizer_t]
)
