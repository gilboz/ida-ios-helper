__all__ = ["baseline_modules_component"]

from ioshelper.base.reloadable_plugin import StartupScriptComponent

from .baseline import offer_to_load_missing_baseline

baseline_modules_component = StartupScriptComponent.factory(
    "dsc-baseline-modules",
    "On a partial dyld_shared_cache, offer once to load the important unloaded baseline modules",
    [offer_to_load_missing_baseline],
    ui_only=True,
)
