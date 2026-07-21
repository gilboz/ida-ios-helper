"""
Plugin configuration loaded from the user's IDA directory.

The plugin reads a single optional TOML file at `~/.idapro/ioshelper.cfg` when it
loads. The file is parsed once into a `Config` and exposed as the module-level
`config` singleton. When the file is absent or unreadable the built-in defaults
apply, so a missing config is never an error.

Besides the top-level keys, any TOML table named after a component is that component's
own settings (`component_options`); the `Config` itself stays agnostic of what each
component puts in its table. A component declares its section's schema as a
`ComponentOptions` dataclass and loads it with `MyOptions.load()`, which validates the
raw table (unknown keys, wrong types) against the declared fields.

Example:
    Enable debug mode, drop Swift support, and turn on one of the lvar renamer's
    experimental name sources when reversing a pure Obj-C binary:

        debug = true
        disabled_features = ["swift"]
        disabled_components = ["swift-strings", "objc-optimizers"]

        [objc-lvar-renamer]
        getters = true
"""

import dataclasses
import tomllib
import typing
from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Any, ClassVar, Self

import ida_diskio

CONFIG_PATH = Path(ida_diskio.get_user_idadir()) / "ioshelper.cfg"


class Feature(StrEnum):
    """A coarse group of components that can be enabled or disabled as a whole."""

    OBJC = "objc"
    SWIFT = "swift"


@dataclass(frozen=True, slots=True)
class Config:
    """
    Parsed contents of the plugin configuration file.

    Attributes:
        debug: Enable development conveniences: the F2 reload and F4 toggle hotkeys
            and debug-only components.
        disabled_features: Feature groups to skip entirely (see `Feature`).
        disabled_components: Names of individual components to skip when loading the
            plugin core.
        experimental_components: Names of work-in-progress components to opt into. These
            are disabled by default and only loaded when listed here.
        component_options: Per-component settings: every top-level TOML table, keyed by
            the component name it is named after. The schema of each table is owned by
            its component, not by the config.
    """

    debug: bool = False
    disabled_features: frozenset[Feature] = frozenset()
    disabled_components: frozenset[str] = frozenset()
    experimental_components: frozenset[str] = frozenset()
    component_options: Mapping[str, Mapping[str, Any]] = field(default_factory=dict)

    def is_feature_enabled(self, feature: Feature) -> bool:
        """
        Return whether the components belonging to `feature` should be loaded.

        Args:
            feature: The feature group to check.

        Returns:
            `True` unless `feature` is listed in `disabled_features`.
        """
        return feature not in self.disabled_features

    def is_component_enabled(self, name: str) -> bool:
        """
        Return whether the component named `name` should be loaded.

        Args:
            name: The component's name.

        Returns:
            `True` unless `name` is listed in `disabled_components`.
        """
        return name not in self.disabled_components

    def is_experimental_enabled(self, name: str) -> bool:
        """
        Return whether the experimental component named `name` should be loaded.

        Experimental components are work-in-progress and disabled by default; they are
        loaded only when opted into via `experimental_components`.

        Args:
            name: The component's name.

        Returns:
            `True` only when `name` is listed in `experimental_components`.
        """
        return name in self.experimental_components

    def options_for(self, component_name: str) -> Mapping[str, Any]:
        """
        Return the component's own settings table, `{}` when the config has none.

        Args:
            component_name: The component's name, i.e. its TOML table's name.

        Returns:
            The raw parsed table. The component owns its schema: it is responsible for
            defaults, type checks, and warning about keys it does not recognize.
        """
        return self.component_options.get(component_name, {})

    @classmethod
    def load(cls, path: Path = CONFIG_PATH) -> Self:
        """
        Parse the configuration file, falling back to defaults on any error.

        Args:
            path: Path to the TOML config file. Defaults to `CONFIG_PATH`.

        Returns:
            The parsed config, or a default-valued config when `path` is missing,
            unreadable, or malformed.
        """
        if not path.exists():
            return cls()

        try:
            with path.open("rb") as f:
                data = tomllib.load(f)
        except (OSError, tomllib.TOMLDecodeError) as e:
            print(f"[iOSHelper] failed to read config at {path}: {e}. Using defaults.")
            return cls()

        return cls(
            debug=bool(data.get("debug", False)),
            disabled_features=_parse_features(_string_list(data, "disabled_features")),
            disabled_components=frozenset(_string_list(data, "disabled_components")),
            experimental_components=frozenset(_string_list(data, "experimental_components")),
            component_options={key: value for key, value in data.items() if isinstance(value, dict)},
        )


def _string_list(data: dict[str, Any], key: str) -> list[str]:
    """
    Coerce `data[key]` to a list of strings.

    Args:
        data: The parsed TOML table.
        key: The key to read.

    Returns:
        The value as a list of strings, or an empty list (after a warning) when the
        value is present but is not an array.
    """
    value = data.get(key, [])
    if not isinstance(value, list):
        print(f"[iOSHelper] config: '{key}' must be an array of strings; ignoring it.")
        return []
    return [str(item) for item in value]


def _parse_features(names: list[str]) -> frozenset[Feature]:
    """
    Resolve feature names to `Feature` members.

    Args:
        names: Raw feature names read from the config file.

    Returns:
        The recognized features. Unknown names are warned about and skipped.
    """
    features: set[Feature] = set()
    for name in names:
        try:
            features.add(Feature(name))
        except ValueError:
            known = ", ".join(feature.value for feature in Feature)
            print(f"[iOSHelper] config: unknown feature {name!r}; ignoring it. Known features: {known}.")
    return frozenset(features)


config = Config.load()


class ComponentOptions:
    """
    Declarative schema of a component's own config section.

    A component subclasses this as a frozen dataclass, naming its section (its component
    name) in the class definition. Each dataclass field is one option: its TOML key is
    the field name with underscores spelled as dashes, its default is the field default,
    and its declared type is enforced when loading. Only plain TOML scalar types make
    sense here (`bool`, `int`, `float`, `str`) — not parameterized generics.

        @dataclasses.dataclass(frozen=True)
        class MyOptions(ComponentOptions, section="my-component"):
            threshold: int = 4
            callee_args: bool = False  # `callee-args` in the config file

    `load()` reads the section from the `config` singleton and validates it against the
    declared fields, warning — prefixed with the section name — about unknown keys and
    wrong-typed values (which fall back to the field's default). Load the options when
    the component loads, so a config mistake is reported once, at load time, not on
    every use.
    """

    _section: ClassVar[str]

    def __init_subclass__(cls, *, section: str, **kwargs: Any) -> None:
        super().__init_subclass__(**kwargs)
        cls._section = section

    @classmethod
    def load(cls) -> Self:
        """
        Read and validate the component's section, falling back to defaults per key.

        Returns:
            The options instance: declared defaults overlaid with the section's valid
            values. Unknown keys and wrong-typed values are warned about and skipped.
        """
        raw = config.options_for(cls._section)
        hints = typing.get_type_hints(cls)
        fields_by_key = {f.name.replace("_", "-"): f for f in dataclasses.fields(cls)}

        for key in sorted(raw.keys() - fields_by_key.keys()):
            known = ", ".join(fields_by_key)
            print(f"[{cls._section}] config: unknown option {key!r}; ignoring it. Known options: {known}.")

        values: dict[str, Any] = {}
        for key, f in fields_by_key.items():
            if key not in raw:
                continue
            value = raw[key]
            expected = hints[f.name]
            if not _matches_option_type(value, expected):
                print(
                    f"[{cls._section}] config: {key!r} must be of type {expected.__name__}, got {value!r}; "
                    f"using the default ({f.default!r})."
                )
                continue
            values[f.name] = value
        return cls(**values)


def _matches_option_type(value: Any, expected: type) -> bool:
    """
    Return whether a raw TOML `value` satisfies an option field's declared type.

    A plain `isinstance` check, except that `bool` is not accepted for `int`/`float`
    fields (`bool` subclasses `int`, but `threshold = true` is a config mistake).
    """
    if expected in (int, float) and isinstance(value, bool):
        return False
    return isinstance(value, expected)
