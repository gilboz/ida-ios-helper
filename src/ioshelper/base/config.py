"""
Plugin configuration loaded from the user's IDA directory.

The plugin reads a single optional TOML file at ``~/.idapro/ioshelper.cfg`` when it
loads. The file is parsed once into a ``Config`` and exposed as the module-level
``config`` singleton. When the file is absent or unreadable the built-in defaults
apply, so a missing config is never an error.

Example:
    Enable debug mode and drop Swift support when reversing a pure Obj-C binary::

        debug = true
        disabled_features = ["swift"]
        disabled_components = ["SwiftStrings", "Obj-C refcount optimizer"]
"""

import tomllib
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Any, Self

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
        disabled_features: Feature groups to skip entirely (see ``Feature``).
        disabled_components: Names of individual components to skip when loading the
            plugin core.
    """

    debug: bool = False
    disabled_features: frozenset[Feature] = frozenset()
    disabled_components: frozenset[str] = frozenset()

    def is_feature_enabled(self, feature: Feature) -> bool:
        """
        Return whether the components belonging to ``feature`` should be loaded.

        Args:
            feature: The feature group to check.

        Returns:
            ``True`` unless ``feature`` is listed in ``disabled_features``.
        """
        return feature not in self.disabled_features

    def is_component_enabled(self, name: str) -> bool:
        """
        Return whether the component named ``name`` should be loaded.

        Args:
            name: The component's name.

        Returns:
            ``True`` unless ``name`` is listed in ``disabled_components``.
        """
        return name not in self.disabled_components

    @classmethod
    def load(cls, path: Path = CONFIG_PATH) -> Self:
        """
        Parse the configuration file, falling back to defaults on any error.

        Args:
            path: Path to the TOML config file. Defaults to ``CONFIG_PATH``.

        Returns:
            The parsed config, or a default-valued config when ``path`` is missing,
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
        )


def _string_list(data: dict[str, Any], key: str) -> list[str]:
    """
    Coerce ``data[key]`` to a list of strings.

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
    Resolve feature names to ``Feature`` members.

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
