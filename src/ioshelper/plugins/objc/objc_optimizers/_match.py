__all__ = ["match_func_name"]

import re

from ioshelper.base.utils import match

# Compiler/IDA decorations that wrap the helper names we match on; stripped before matching.
PREFIXES_TO_IGNORE: list[str] = [
    "_",
    "__",
    "j_",
    "j__",
]

_SORTED_PREFIXES = sorted(PREFIXES_TO_IGNORE, key=len, reverse=True)

_SUFFIXES_TO_IGNORE: list[str | re.Pattern] = [
    re.compile(r"_x\d{1,2}$"),
    re.compile(r"_\d+$"),
]


def match_func_name(arr: list[str | re.Pattern], name: str) -> bool:
    """Match ``name`` against ``arr`` after stripping a leading decoration prefix and trailing suffix.

    Args:
        arr: Names/patterns to match against (see :func:`ioshelper.base.utils.match`).
        name: The raw call target name, possibly carrying a ``_``/``j_`` prefix and an ``_N``/``_xN`` suffix.

    Returns:
        Whether the normalized name matches an entry in ``arr``.
    """
    for prefix in _SORTED_PREFIXES:
        if name.startswith(prefix):
            name = name[len(prefix) :]
            break
    for suffix in _SUFFIXES_TO_IGNORE:
        if isinstance(suffix, str):
            if name.endswith(suffix):
                name = name[: -len(suffix)]
                break
        else:
            m = suffix.search(name)
            if m is not None and m.end() == len(name):
                name = name[: m.start()]
                break

    return match(arr, name)
