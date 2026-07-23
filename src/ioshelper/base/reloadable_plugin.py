# This code was inspired by Lucid's plugin core, which is licensed under the MIT License.
# However, this is a complete rewrite that only contains the _startup_hooks part from the original code.
# As such, I find it acceptable to use this code under the same license as the rest of the plugin.
# https://github.com/gaasedelen/lucid/blob/master/plugins/lucid/core.py
import abc
import contextlib
import dataclasses
import sys
from collections.abc import Callable
from datetime import datetime
from typing import Generic, Protocol, TypeVar, cast, overload

import ida_hexrays
import ida_idaapi
import ida_kernwin
import idaapi
from ida_idaapi import plugin_t
from ida_kernwin import UI_Hooks, action_desc_t
from idahelper import runtime

from .config import ComponentOptions, config

OptionsT = TypeVar("OptionsT", bound=ComponentOptions)


class Component:
    """
    A component is a self-contained piece of functionality that can be loaded and unloaded independently.
    It will only be loaded and unloaded when the plugin core is loaded and unloaded.
    However, it can be mounted and unmounted independently of the plugin core.

    Attributes:
        name: Short identifier (slug) used in the config file (`disabled_components`,
            `experimental_components`) and in load/mount logs.
        description: Human-readable summary of what the component does.
        core: The plugin core that owns this component.
        ui_only: Whether the component is only meaningful with a UI present; ui-only
            components are skipped entirely when running headless (idalib/idat).
    """

    def __init__(self, name: str, description: str, core: "PluginCore", *, ui_only: bool = False):
        self.name = name
        self.description = description
        self.core = core
        self.ui_only = ui_only

    def load(self) -> bool:
        """Load the component and all the relevant resources"""
        return True

    def mount(self) -> bool:
        """Enable the functionality of the component"""
        return True

    def unmount(self):
        """Disable the functionality of the component"""
        pass

    def unload(self):
        """Unload the component and all the relevant resources"""
        pass


ComponentFactory = Callable[["PluginCore"], Component]
RunCallbackFactory = Callable[["PluginCore"], Callable[[int], None]]


class PluginCoreFactory(Protocol):
    def __call__(self, defer_load: bool, should_mount: bool) -> float: ...


class PluginCore:
    def __init__(
        self,
        name: str,
        component_factories: list[ComponentFactory],
        run_callback_factory: RunCallbackFactory,
        defer_load: bool = False,
        should_mount: bool = True,
    ):
        self.name = name
        self.run_callback = run_callback_factory(self)
        self.loaded = False
        self.mounted = False
        all_components = [factory(self) for factory in component_factories]
        components = [component for component in all_components if config.is_component_enabled(component.name)]
        if runtime.is_headless():
            skipped = [component.name for component in components if component.ui_only]
            if skipped:
                print(f"[{name}] headless mode, skipping ui-only components: {', '.join(skipped)}")
            components = [component for component in components if not component.ui_only]
        self._components = components

        # we can 'defer' the load of the plugin core a little bit. this
        # ensures that all the other plugins (eg, decompilers) can get loaded
        # and initialized when opening an idb/bin

        def perform_load():
            self.load()
            if should_mount:
                self.mount()

        class UIHooks(UI_Hooks):
            def ready_to_run(self):
                perform_load()

        self._startup_hooks = UIHooks()

        if defer_load:
            self._startup_hooks.hook()
        else:
            perform_load()

    def load(self):
        self._startup_hooks.unhook()

        if not ida_hexrays.init_hexrays_plugin():
            print(f"[{self.name}] failed to load hex-rays plugin, aborting load.")
            return

        print(f"[{self.name}] loading plugin")
        for component in self._components:
            print(f"[{self.name}] loading component {component.name}")
            if not component.load():
                print(f"[{self.name}] failed to load component {component.name}, aborting load.")
                return

        self.loaded = True

    def mount(self):
        if not self.mounted:
            for component in self._components:
                if self.should_mount(component):
                    print(f"[{self.name}] mounting component {component.name}")
                    if not component.mount():
                        print(f"[{self.name}] failed to mount component {component.name}, aborting mount.")
                        return
            self.mounted = True

    def unmount(self):
        if self.mounted:
            for component in self._components:
                print(f"[{self.name}] unmounting component {component.name}")
                component.unmount()

            self.mounted = False

    def unload(self):
        """Unload the plugin core."""

        # unhook just in-case load() was never actually called...
        self._startup_hooks.unhook()

        # if the core was never fully loaded, there's nothing else to do
        if not self.loaded:
            return

        print(f"[{self.name}] unloading plugin")

        # mark the core as 'unloaded' and teardown its components
        self.loaded = False

        self.unmount()
        for component in self._components:
            print(f"[{self.name}] unloading component {component.name}")
            component.unload()

    def should_mount(self, _component: Component) -> bool:
        """
        Determine if a component should be mounted based on the current state of the plugin core.
        In the future, we will implement a more sophisticated system to determine if a component should be mounted.
        """
        return True

    def run(self, arg: int):
        """Proxy for the `run` method of the plugin_t interface."""
        self.run_callback(arg)

    @staticmethod
    def factory(
        name: str, component_factories: list[ComponentFactory], run_callback_factory: RunCallbackFactory
    ) -> PluginCoreFactory:
        def plugin_core_factory(defer_load: bool, should_mount: bool) -> PluginCore:
            return PluginCore(
                name, component_factories, run_callback_factory, defer_load=defer_load, should_mount=should_mount
            )

        # The type checker seems to have trouble with the factory method, so we need to suppress it
        # noinspection PyTypeChecker
        return plugin_core_factory


class ReloadablePlugin(abc.ABC, plugin_t):
    def __init__(
        self,
        global_name: str,
        base_package_name: str,
        plugin_core_factory: PluginCoreFactory,
        extra_packages_to_reload: list[str] | None = None,
    ):
        super().__init__()
        self._global_name = global_name
        self._plugin_core_factory = plugin_core_factory
        self._base_package_name = base_package_name
        self.core: PluginCore | None = None
        self._reload_plugin_action_id = f"{self._global_name}:reload_plugin"
        self.extra_packages_to_reload = extra_packages_to_reload or []

    def init(self) -> int:
        self.core = self._plugin_core_factory(defer_load=True, should_mount=True)
        # Provide access from ida python console
        setattr(sys.modules["__main__"], self._global_name, self)
        # register the reload action
        idaapi.register_action(
            idaapi.action_desc_t(
                self._reload_plugin_action_id,
                f"Reload plugin: {getattr(self, 'wanted_name', self._global_name)}",
                PluginReloadActionHandler(self),
                "f2" if config.debug else None,
            )
        )
        # Keep plugin alive
        return ida_idaapi.PLUGIN_KEEP

    def term(self) -> None:
        idaapi.unregister_action(self._reload_plugin_action_id)
        if self.core is not None:
            self.core.unload()

    def run(self, arg: int):
        if self.core is not None:
            self.core.run(arg)

    def reload(self):
        """Hot-reload the plugin core."""
        print(f"[{getattr(self, 'wanted_name', 'plugin')}] Reloading...")

        # Unload the core and all its components
        was_mounted = self.core.mounted if self.core else True
        if self.core is not None:
            self.core.unload()

        # Reload all modules in the base package
        modules_to_reload = [module_name for module_name in sys.modules if self.should_reload_pkg(module_name)]
        for module_name in modules_to_reload:
            with contextlib.suppress(ModuleNotFoundError):
                idaapi.require(module_name)

        # Load the plugin core
        self.core = self._plugin_core_factory(defer_load=False, should_mount=was_mounted)

    def should_reload_pkg(self, module_name: str) -> bool:
        """Should we reload this module on reloading the plugin?"""
        if module_name.startswith(self._base_package_name):
            return True
        return any(module_name.startswith(prefix) for prefix in self.extra_packages_to_reload)


class PluginReloadActionHandler(ida_kernwin.action_handler_t):
    def __init__(self, plugin: ReloadablePlugin):
        super().__init__()
        self.plugin = plugin

    def activate(self, ctx):
        self.plugin.reload()
        print(f"Reloaded plugin! ({datetime.now():%H:%M:%S})")
        return 1

    def update(self, ctx) -> int:
        return idaapi.AST_ENABLE_ALWAYS


# A common type of component is installing optimizers for the decompiler. This is a helper class to make it easier.

optimizer_t = ida_hexrays.optblock_t | ida_hexrays.optinsn_t
optimizer_factory_t = Callable[[], optimizer_t]


class OptimizersComponent(Component):
    def __init__(self, name: str, description: str, core: PluginCore, optimizer_factories: list[optimizer_factory_t]):
        super().__init__(name, description, core)
        self._optimizer_factories = optimizer_factories
        self._optimizers: list[optimizer_t] | None = None

    def load(self) -> bool:
        self._optimizers = [factory() for factory in self._optimizer_factories]
        return True

    def mount(self) -> bool:
        assert self._optimizers is not None, "Load must be called before mount"

        for optimizer in self._optimizers:
            optimizer.install()
        return True

    def unmount(self):
        assert self._optimizers is not None, "Load must be called before unmount"

        for optimizer in self._optimizers:
            optimizer.remove()

    def unload(self):
        self._optimizers = None

    @staticmethod
    def factory(name: str, description: str, optimizer_factories: list[optimizer_factory_t]) -> ComponentFactory:
        return lambda core: OptimizersComponent(name, description, core, optimizer_factories)


@dataclasses.dataclass
class UIAction:
    id: str
    action_desc: action_desc_t
    menu_location: str | None = None
    dynamic_menu_add: Callable[["TWidget *", "TPopupMenu *"], bool] | None = None  # noqa: F722

    @staticmethod
    def base_location(core: PluginCore) -> str:
        """
        Returns the base location for the plugin's UI actions.
        This is used to create a unique menu location for the actions.
        """
        return f"Edit/Plugins/{core.name}/"


class UIActionsComponentUIHooks(idaapi.UI_Hooks):
    def __init__(self, actions: list[UIAction]):
        super().__init__()
        self._actions = actions

    def finish_populating_widget_popup(self, widget, popup):
        for action in self._actions:
            if action.dynamic_menu_add is not None and action.dynamic_menu_add(widget, popup):
                idaapi.attach_action_to_popup(widget, popup, action.id)


# Another common type of component is installing ui actions. This is a helper class to make it easier.
class UIActionsComponent(Component, Generic[OptionsT]):
    """
    A component registering menu actions / hotkeys.

    Args:
        name: Short identifier (slug) used in the config file and load/mount logs.
        description: Human-readable summary of what the component does.
        core: The plugin core that owns this component.
        action_factories: The factories building the actions, called once at load
            time. Without an `options` schema each factory takes the core; with one,
            each factory also receives the resolved options.
        options: The component's `ComponentOptions` schema, resolved once at load
            time and passed to every action factory.
    """

    def __init__(
        self,
        name: str,
        description: str,
        core: PluginCore,
        action_factories: list[Callable[[PluginCore], UIAction]] | list[Callable[[PluginCore, OptionsT], UIAction]],
        *,
        options: type[OptionsT] | None = None,
    ):
        # Menu actions and popup hooks have no meaning without a UI.
        super().__init__(name, description, core, ui_only=True)
        self._action_factories = action_factories
        self._actions: list[UIAction] | None = None
        self._ui_hooks: UI_Hooks | None = None
        self._options_schema = options

    def load(self) -> bool:
        if self._options_schema is None:
            factories = cast("list[Callable[[PluginCore], UIAction]]", self._action_factories)
            self._actions = [factory(self.core) for factory in factories]
        else:
            options = self._options_schema.load()
            factories = cast("list[Callable[[PluginCore, OptionsT], UIAction]]", self._action_factories)
            self._actions = [factory(self.core, options) for factory in factories]
        if any(action.dynamic_menu_add is not None for action in self._actions):
            # Create a UI_Hooks instance to attach the dynamic menu
            self._ui_hooks = UIActionsComponentUIHooks(self._actions)
            self._ui_hooks.hook()

        for action in self._actions:
            if not idaapi.register_action(action.action_desc):
                print(f"[{self.name}] failed to register action {action.id}, aborting load.")
                return False

            if action.menu_location is not None and not idaapi.attach_action_to_menu(
                action.menu_location,
                action.id,
                0,
            ):
                print(
                    f"[{self.name}] failed to attach action {action.id} to menu {action.menu_location}, aborting load."
                )
                return False

        return True

    def unload(self):
        for action in self._actions:
            idaapi.unregister_action(action.id)

        if self._ui_hooks is not None:
            self._ui_hooks.unhook()

    @overload
    @staticmethod
    def factory(
        name: str, description: str, action_factories: list[Callable[[PluginCore], UIAction]]
    ) -> ComponentFactory: ...

    @overload
    @staticmethod
    def factory(
        name: str,
        description: str,
        action_factories: list[Callable[[PluginCore, OptionsT], UIAction]],
        *,
        options: type[OptionsT],
    ) -> ComponentFactory: ...

    @staticmethod
    def factory(
        name: str,
        description: str,
        action_factories: list[Callable[[PluginCore], UIAction]] | list[Callable[[PluginCore, OptionsT], UIAction]],
        *,
        options: type[OptionsT] | None = None,
    ) -> ComponentFactory:
        return lambda core: UIActionsComponent(name, description, core, action_factories, options=options)


# A common type of component is installing hooks for the decompiler. This is a helper class to make it easier.
class HexraysHookComponent(Component, Generic[OptionsT]):
    """
    A component installing `Hexrays_Hooks` on mount.

    Args:
        name: Short identifier (slug) used in the config file and load/mount logs.
        description: Human-readable summary of what the component does.
        core: The plugin core that owns this component.
        hook_factories: The factories building the hooks, called once at load time.
            Without an `options` schema each factory takes no arguments; with one,
            each factory receives the resolved options and may return `None` to opt
            its hook out (e.g. when an option disables it).
        ui_only: Whether the hooks only listen to the pseudocode-view events, which
            never fire headless; such a component is skipped when running headlessly.
        options: The component's `ComponentOptions` schema, resolved once at load
            time and passed to every hook factory.
    """

    def __init__(
        self,
        name: str,
        description: str,
        core: PluginCore,
        hook_factories: list[Callable[[], ida_hexrays.Hexrays_Hooks]]
        | list[Callable[[OptionsT], ida_hexrays.Hexrays_Hooks | None]],
        *,
        ui_only: bool = False,
        options: type[OptionsT] | None = None,
    ):
        super().__init__(name, description, core, ui_only=ui_only)
        self._hook_factories = hook_factories
        self._hooks: list[ida_hexrays.Hexrays_Hooks] | None = None
        self._options_schema = options

    def load(self):
        if self._options_schema is None:
            factories = cast("list[Callable[[], ida_hexrays.Hexrays_Hooks]]", self._hook_factories)
            self._hooks = [factory() for factory in factories]
        else:
            options = self._options_schema.load()
            factories = cast("list[Callable[[OptionsT], ida_hexrays.Hexrays_Hooks | None]]", self._hook_factories)
            self._hooks = [hook for factory in factories if (hook := factory(options)) is not None]
        return True

    def mount(self) -> bool:
        assert self._hooks is not None, "load() must be called before mount()"
        for hook in self._hooks:
            hook.hook()
        return True

    def unmount(self):
        if self._hooks is not None:
            for hook in self._hooks:
                hook.unhook()

    def unload(self):
        self._hooks = None

    @overload
    @staticmethod
    def factory(
        name: str,
        description: str,
        hook_factories: list[Callable[[], ida_hexrays.Hexrays_Hooks]],
        *,
        ui_only: bool = False,
    ) -> ComponentFactory: ...

    @overload
    @staticmethod
    def factory(
        name: str,
        description: str,
        hook_factories: list[Callable[[OptionsT], ida_hexrays.Hexrays_Hooks | None]],
        *,
        ui_only: bool = False,
        options: type[OptionsT],
    ) -> ComponentFactory: ...

    @staticmethod
    def factory(
        name: str,
        description: str,
        hook_factories: list[Callable[[], ida_hexrays.Hexrays_Hooks]]
        | list[Callable[[OptionsT], ida_hexrays.Hexrays_Hooks | None]],
        *,
        ui_only: bool = False,
        options: type[OptionsT] | None = None,
    ) -> ComponentFactory:
        return lambda core: HexraysHookComponent(
            name, description, core, hook_factories, ui_only=ui_only, options=options
        )


class StartupScriptComponent(Component):
    def __init__(
        self,
        name: str,
        description: str,
        core: PluginCore,
        callbacks: list[Callable[[], None]],
        *,
        ui_only: bool = False,
    ):
        # A callback that only makes sense with a UI (e.g. it prompts the user) sets this so
        # it is skipped when mounting headlessly, like the ui-action components.
        super().__init__(name, description, core, ui_only=ui_only)
        self._callbacks = callbacks

    def load(self):
        return True

    def mount(self) -> bool:
        for callback in self._callbacks:
            callback()
        return True

    def unmount(self):
        pass

    def unload(self):
        pass

    @staticmethod
    def factory(
        name: str, description: str, callbacks: list[Callable[[], None]], *, ui_only: bool = False
    ) -> ComponentFactory:
        return lambda core: StartupScriptComponent(name, description, core, callbacks, ui_only=ui_only)
