__all__ = ["range_condition_optimizer_component"]

from ioshelper.base.reloadable_plugin import HexraysHookComponent

from .range_condition import range_condition_optimizer

range_condition_optimizer_component = HexraysHookComponent.factory(
    "range-condition-optimizer",
    "Simplify range-check conditions in the decompiler",
    [range_condition_optimizer],
)
