"""
The prioritized Obj-C lvar renaming pipeline.

Runs once per decompilation (from `ObjcLvarRenameHook` at `CMAT_FINAL`) and merges the
name sources in priority order — the function's own selector (args), getters, callee
keyword arguments — into a single batch of renames. A variable that already carries a
non-default name is never touched, and when several sources want to name the same
variable the highest-priority one wins.

Each source is gated like a component, by its own name in the config: listing it in
`disabled_components` turns it off, and the experimental ones are off by default until
listed in `experimental_components`.
"""

__all__ = [
    "OBJC_RENAME_ARGS_SOURCE_NAME",
    "OBJC_RENAME_CALLEE_ARGS_SOURCE_NAME",
    "OBJC_RENAME_GETTERS_SOURCE_NAME",
    "rename_objc_lvars_during_decompilation",
]

from ida_hexrays import cfunc_t, lvars_t
from idahelper import memory, naming
from idahelper.ast import lvars
from idahelper.ast.lvars import VariableModification

from ioshelper.base.config import config

from .args_source import collect_arg_candidates
from .call_sources import collect_call_candidates
from .heuristics import DEFAULT_LVAR_NAME

OBJC_RENAME_ARGS_SOURCE_NAME = "objc-rename-args"
OBJC_RENAME_GETTERS_SOURCE_NAME = "objc-rename-getters"
OBJC_RENAME_CALLEE_ARGS_SOURCE_NAME = "objc-rename-callee-args"


def rename_objc_lvars_during_decompilation(decompiled: cfunc_t) -> bool:
    """
    Rename the still-default-named lvars of `decompiled` from the enabled name sources.

    For use inside a decompilation event (e.g. a `maturity` hook): the renames are written
    through the saved-settings fast path and patched onto the live `lvar_t`s, so no extra
    decompilation is triggered.

    Args:
        decompiled: The function's in-flight decompilation.

    Returns:
        `True` if at least one variable was renamed.
    """
    want_args = _is_source_enabled(OBJC_RENAME_ARGS_SOURCE_NAME)
    want_getters = _is_source_enabled(OBJC_RENAME_GETTERS_SOURCE_NAME, experimental=True)
    want_callee_args = _is_source_enabled(OBJC_RENAME_CALLEE_ARGS_SOURCE_NAME, experimental=True)
    if not (want_args or want_getters or want_callee_args):
        return False

    func_lvars = decompiled.get_lvars()
    arg_candidates = collect_arg_candidates(decompiled) if want_args else {}
    getter_candidates: dict[str, str] = {}
    callee_arg_candidates: dict[str, str] = {}
    if want_getters or want_callee_args:
        getter_candidates, callee_arg_candidates = collect_call_candidates(
            decompiled, func_lvars, want_getters=want_getters, want_callee_args=want_callee_args
        )

    # Merge in priority order: the first source to name a variable wins.
    candidates: dict[str, tuple[str, str]] = {}
    for source, source_candidates in (
        ("args", arg_candidates),
        ("getters", getter_candidates),
        ("callee-args", callee_arg_candidates),
    ):
        for current, base_name in source_candidates.items():
            if current not in candidates:
                candidates[current] = (base_name, source)
    if not candidates:
        return False

    modifications = _build_modifications(func_lvars, candidates)
    renamed = lvars.perform_lvar_modifications_during_decompilation(decompiled.entry_ea, func_lvars, modifications)
    if renamed and config.debug:
        summary = ", ".join(f"{old} -> {mod.name} ({candidates[old][1]})" for old, mod in modifications.items())
        print(f"[Debug] objc-lvar-renamer: {memory.name_from_ea(decompiled.entry_ea)}: {summary}")
    return renamed


def _is_source_enabled(name: str, *, experimental: bool = False) -> bool:
    """
    Return whether the name source `name` is enabled per the config.

    Sources are gated by the same lists as components: `disabled_components` disables one,
    and the experimental ones additionally require an `experimental_components` opt-in.
    """
    if not config.is_component_enabled(name):
        return False
    return not experimental or config.is_experimental_enabled(name)


def _build_modifications(
    func_lvars: lvars_t, candidates: dict[str, tuple[str, str]]
) -> dict[str, VariableModification]:
    """Turn `{current name: (base name, source)}` into modifications, de-duplicating names."""
    taken = {
        func_lvars[i].name
        for i in range(func_lvars.size())
        if func_lvars[i].name and not DEFAULT_LVAR_NAME.match(func_lvars[i].name)
    }
    modifications: dict[str, VariableModification] = {}
    for current, (base_name, _source) in candidates.items():
        name = naming.unique_name(base_name, taken)
        taken.add(name)
        modifications[current] = VariableModification(name=name)
    return modifications
