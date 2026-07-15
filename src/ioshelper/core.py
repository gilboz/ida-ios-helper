__all__ = ["plugin_core"]

import ida_kernwin
import idaapi
from idahelper import file_format, widgets

from .base.config import Feature, config
from .base.reloadable_plugin import ComponentFactory, PluginCore, UIAction, UIActionsComponent
from .plugins.common.clang_blocks import clang_block_args_analyzer_component, clang_block_optimizer_component
from .plugins.common.globals import globals_component
from .plugins.common.jump_to_string import jump_to_string_component
from .plugins.common.outline import mark_outline_functions_component
from .plugins.common.range_condition import range_condition_optimizer_component
from .plugins.common.run_callback import run_callback
from .plugins.common.segment_xrefs import show_segment_xrefs_component
from .plugins.dsc.baseline_modules import baseline_modules_component
from .plugins.dsc.organize_functions import organize_functions_component
from .plugins.dsc.stub_calls import STUB_CALLS_COMPONENT_NAME, stub_calls_component
from .plugins.dsc.stub_modules import report_stub_modules_component
from .plugins.kernelcache.cpp_vtbl import jump_to_vtable_component
from .plugins.kernelcache.func_renamers import (
    apply_pac_component,
    local_func_renamer_component,
    mass_func_renamer_component,
)
from .plugins.kernelcache.generic_calls_fix import generic_calls_fix_component
from .plugins.kernelcache.kalloc_type import apply_kalloc_type_component, create_type_from_kalloc_component
from .plugins.kernelcache.obj_this import this_arg_fixer_component
from .plugins.objc.objc_arg_renamer import mass_objc_arg_renamer_component, objc_arg_renamer_component
from .plugins.objc.objc_msgsend_args import (
    OBJC_MSGSEND_ARGCOUNT_COMPONENT_NAME,
    objc_msgsend_argcount_component,
)
from .plugins.objc.objc_optimizers import component as objc_optimizers_component
from .plugins.objc.objc_ref import objc_xrefs_component
from .plugins.objc.objc_sugar import objc_sugar_component
from .plugins.objc.oslog import component as oslog_component
from .plugins.swift.swift_dump_import import (
    swift_dump_config_component,
    swift_dump_import_component,
)
from .plugins.swift.swift_oslog import swift_oslog_hook_component
from .plugins.swift.swift_strings import swift_strings_component
from .plugins.swift.swift_types import (
    swift_prolog_hook_component,
    swift_types_component,
    swift_types_hook_component,
)

TOGGLE_ACTION_ID = "ioshelper:toggle"

toggle_ios_helper_mount_component = UIActionsComponent.factory(
    "toggle-mount",
    "Toggle the plugin's optimizations on/off at runtime",
    [
        lambda core: UIAction(
            TOGGLE_ACTION_ID,
            idaapi.action_desc_t(
                TOGGLE_ACTION_ID,
                "Toggle iOS helper optimizations",
                IOSHelperToggleActionHandler(core),
                "f4" if config.debug else None,
            ),
            menu_location=UIAction.base_location(core),
        )
    ],
)


class IOSHelperToggleActionHandler(ida_kernwin.action_handler_t):
    def __init__(self, core: PluginCore):
        super().__init__()
        self.core = core

    def activate(self, ctx):
        if self.core.mounted:
            self.core.unmount()
        else:
            self.core.mount()

        widgets.refresh_pseudocode_widgets()

        print("Obj-C optimization are now:", "enabled" if self.core.mounted else "disabled")
        print("Note: You might need to perform decompile again for this change to take effect.")
        return 1

    def update(self, ctx) -> int:
        return idaapi.AST_ENABLE_ALWAYS


def get_modules_for_file() -> list[ComponentFactory]:
    is_dsc = file_format.is_dsc()
    enable_objc = (is_dsc or file_format.is_objc()) and config.is_feature_enabled(Feature.OBJC)
    enable_swift = (is_dsc or file_format.is_swift()) and config.is_feature_enabled(Feature.SWIFT)
    return [
        *shared_modules(),
        *(objc_plugins() if enable_objc else []),
        *(swift_plugins() if enable_swift else []),
        *(kernel_cache_plugins() if file_format.is_kernelcache() else []),
        *(dsc_plugins() if is_dsc else []),
    ]


def shared_modules() -> list[ComponentFactory]:
    modules = [
        this_arg_fixer_component,
        toggle_ios_helper_mount_component,
        clang_block_args_analyzer_component,
        clang_block_optimizer_component,
        jump_to_string_component,
        range_condition_optimizer_component,
        mark_outline_functions_component,
        show_segment_xrefs_component,
    ]
    if config.debug:
        from ioshelper.debug import dump_ps_component

        modules.append(dump_ps_component)
    return modules


def objc_plugins() -> list[ComponentFactory]:
    plugins: list[ComponentFactory] = [
        oslog_component,
        objc_xrefs_component,
        objc_optimizers_component,
        objc_arg_renamer_component,
        mass_objc_arg_renamer_component,
        objc_sugar_component,
    ]
    # WIP: selector-driven objc_msgSend arg-count fixup is unreliable, so it is opt-in.
    if config.is_experimental_enabled(OBJC_MSGSEND_ARGCOUNT_COMPONENT_NAME):
        plugins.append(objc_msgsend_argcount_component)
    return plugins


def swift_plugins() -> list[ComponentFactory]:
    return [
        swift_types_component,
        swift_types_hook_component,
        swift_prolog_hook_component,
        swift_oslog_hook_component,
        swift_strings_component,
        swift_dump_import_component,
        swift_dump_config_component,
    ]


def dsc_plugins() -> list[ComponentFactory]:
    plugins: list[ComponentFactory] = [
        organize_functions_component,
        # Reporting which modules back a function's stubs needs the dscu service (IDA 9.4+);
        # on older IDA the action degrades to a one-line "requires 9.4+" message.
        report_stub_modules_component,
        # On open, offer to load the important baseline modules a partial cache is missing.
        baseline_modules_component,
    ]
    # WIP: stub-call retargeting is unreliable, so it is opt-in.
    if config.is_experimental_enabled(STUB_CALLS_COMPONENT_NAME):
        plugins.append(stub_calls_component)
    return plugins


def kernel_cache_plugins() -> list[ComponentFactory]:
    return [
        jump_to_vtable_component,
        generic_calls_fix_component,
        local_func_renamer_component,
        mass_func_renamer_component,
        apply_kalloc_type_component,
        apply_pac_component,
        create_type_from_kalloc_component,
        globals_component,
    ]


plugin_core = PluginCore.factory("iOSHelper", get_modules_for_file(), run_callback)
