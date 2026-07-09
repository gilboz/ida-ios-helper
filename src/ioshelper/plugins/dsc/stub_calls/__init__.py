__all__ = ["STUB_CALLS_COMPONENT_NAME", "stub_calls_component"]

from ioshelper.base.reloadable_plugin import OptimizersComponent

from .optimizer import stub_call_optimizer_t

# WIP: retargeting shared-cache import-stub calls to their canonical function is still
# experimental and disabled by default. Opt in by adding this name to
# `experimental_components` in the config.
STUB_CALLS_COMPONENT_NAME = "dsc-stub-calls"

stub_calls_component = OptimizersComponent.factory(
    STUB_CALLS_COMPONENT_NAME,
    "Retarget dyld-shared-cache import-stub calls to the real function with a clean name (experimental)",
    [stub_call_optimizer_t],
)
