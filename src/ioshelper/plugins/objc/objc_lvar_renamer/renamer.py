"""
The Obj-C lvar renamer: a `CMAT_FINAL` maturity hook that renames still-default-named
lvars from the enabled name sources in one batch, with zero extra decompilations.
"""

__all__ = ["ObjcLvarRenameHook"]

import ida_hexrays
from ida_hexrays import Hexrays_Hooks, cfunc_t, lvars_t
from idahelper import memory, naming
from idahelper.ast import lvars
from idahelper.ast.lvars import VariableModification, is_default_name

from ioshelper.base.config import config
from ioshelper.base.log import debug

from .args_source import collect_arg_candidates
from .call_sources import collect_call_candidates
from .options import OBJC_LVAR_RENAMER_COMPONENT_NAME, RenamerOptions


class ObjcLvarRenameHook(Hexrays_Hooks):
    """
    Run the renaming pipeline automatically on every decompilation, at `CMAT_FINAL`.

    The component (or a headless probe script) resolves the name-source gates and
    creates the hook when it loads, so a plugin hot-reload after a config change
    picks the new gates up and logs them again.

    Args:
        options: Configuration options that control which sources are used for suggesting new names for Objective-C local variables
    """

    def __init__(self, options: RenamerOptions) -> None:
        super().__init__()
        self._options = options
        self._options.log()

    def maturity(self, cfunc: cfunc_t, new_maturity: int) -> int:
        if new_maturity == ida_hexrays.CMAT_FINAL:
            self._rename_lvars(cfunc)
        return 0

    def _rename_lvars(self, decompiled: cfunc_t) -> bool:
        """
        Rename the still-default-named lvars of `decompiled` from the enabled name sources.

        Runs inside the decompilation event: the renames are written through the
        saved-settings fast path and patched onto the live `lvar_t`s, so no extra
        decompilation is triggered.

        Args:
            decompiled: The function's in-flight decompilation.

        Returns:
            `True` if at least one variable was renamed.
        """
        if not self._options:
            return False

        func_lvars = decompiled.get_lvars()
        candidates, dropped = self._collect_candidates(decompiled, func_lvars)
        if not candidates:
            debug(
                f"{OBJC_LVAR_RENAMER_COMPONENT_NAME}: {memory.name_from_ea(decompiled.entry_ea)}: no rename candidates"
            )
            return False

        modifications = self._build_modifications(func_lvars, candidates)
        renamed = lvars.perform_lvar_modifications_during_decompilation(decompiled.entry_ea, func_lvars, modifications)
        if config.debug:
            self._log_renames(decompiled.entry_ea, candidates, modifications, dropped, renamed=renamed)
        return renamed

    @staticmethod
    def _log_renames(
        entry_ea: int,
        candidates: dict[str, tuple[str, str]],
        modifications: dict[str, VariableModification],
        dropped: list[tuple[str, str, str]],
        *,
        renamed: bool,
    ) -> None:
        """
        Print the decompilation's renames one per line, grouped by the source each name
        came from, plus the proposals that lost their variable to a higher-priority
        source and whether the batch failed to write.
        """
        header = f"{OBJC_LVAR_RENAMER_COMPONENT_NAME}: {memory.name_from_ea(entry_ea)}:"
        if not renamed:
            header += " [nothing written]"
        debug(header)
        by_source: dict[str, list[str]] = {}
        for old, mod in modifications.items():
            by_source.setdefault(candidates[old][1], []).append(f"{old} -> {mod.name}")
        for source, renames in by_source.items():
            debug(f"  {source}:")
            for rename in renames:
                debug(f"    {rename}")
        if dropped:
            debug("  dropped:")
            for var, base, source in dropped:
                debug(f"    {var} -> {base} ({source}, lost to {candidates[var][1]})")

    def _collect_candidates(
        self, decompiled: cfunc_t, func_lvars: lvars_t
    ) -> tuple[dict[str, tuple[str, str]], list[tuple[str, str, str]]]:
        """
        Collect rename candidates from the enabled sources, merged in priority order.

        Args:
            decompiled: The function's in-flight decompilation.
            func_lvars: The decompilation's lvars (`decompiled.get_lvars()`).

        Returns:
            The winning candidates, `{current lvar name: (proposed base name, source label)}`
            — the first source to name a variable wins — and the dropped proposals,
            `(current lvar name, proposed base name, source label)` each, whose variable a
            higher-priority source already claimed.
        """
        arg_candidates = collect_arg_candidates(decompiled) if self._options.args else {}
        getter_candidates: dict[str, str] = {}
        callee_arg_candidates: dict[str, str] = {}
        if self._options.getters or self._options.callee_args:
            getter_candidates, callee_arg_candidates = collect_call_candidates(
                decompiled, func_lvars, want_getters=self._options.getters, want_callee_args=self._options.callee_args
            )

        candidates: dict[str, tuple[str, str]] = {}
        dropped: list[tuple[str, str, str]] = []
        for source, source_candidates in (
            ("args", arg_candidates),
            ("getters", getter_candidates),
            ("callee-args", callee_arg_candidates),
        ):
            for current, base_name in source_candidates.items():
                if current in candidates:
                    dropped.append((current, base_name, source))
                else:
                    candidates[current] = (base_name, source)
        return candidates, dropped

    @staticmethod
    def _build_modifications(
        func_lvars: lvars_t, candidates: dict[str, tuple[str, str]]
    ) -> dict[str, VariableModification]:
        """Turn `{current name: (base name, source)}` into modifications, de-duplicating names."""
        taken = {
            func_lvars[i].name
            for i in range(func_lvars.size())
            if func_lvars[i].name and not is_default_name(func_lvars[i].name)
        }
        modifications: dict[str, VariableModification] = {}
        for current, (base_name, _source) in candidates.items():
            name = naming.unique_name(base_name, taken)
            taken.add(name)
            modifications[current] = VariableModification(name=name)
        return modifications
