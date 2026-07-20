"""
Name default-named local variables from the Obj-C getter/setter they come from.

Two message-send shapes carry an obvious name for the local they touch:

* a **getter** assigns a property to a local -- `v5 = [obj title]` / `v5 = [obj getTitle]`
  names `v5` `title`;
* a **setter** passes a local as the property value -- `[obj setTitle:v5]` names `v5` `title`.

The selector is the name source; the class is not consulted. Names are lowered to
snake_case (`bundleIdentifier` -> `bundle_identifier`, a leading `get` is dropped) and
de-duplicated against the function's other variables. Only variables still holding their
hex-rays default `vN` name are touched, so user renames are never clobbered.

Recognition works on the raw ctree, so it is independent of how IDA spells the call
(`objc_msgSend(recv, "sel", …)`, a resolved `-[Cls sel]`, or an `_objc_msgSend$sel`
stub): in every case the selector is the call's second argument (a string literal) and
the real arguments follow it.
"""

__all__ = ["rename_getters_setters_during_decompilation"]

import re

import ida_hexrays
from ida_hexrays import cexpr_t, cfunc_t, ctree_items_t, ctree_visitor_t, lvars_t
from idahelper import memory, naming, objc
from idahelper.ast import cexpr, citem, lvars
from idahelper.ast.lvars import VariableModification

from ioshelper.base.config import config

# Only hex-rays' default local names (`v5`, `v12`) are renamed -- never arguments (`aN`,
# handled by the objc-arg-renamer), stack slots (`_18`), or anything a user named.
_DEFAULT_LVAR_NAME = re.compile(r"^v\d+$")

# Zero-argument selectors that return an object which is not a property value -- naming a
# local `copy` / `new` after one would mislead, so they are not treated as getters.
_NON_GETTER_SELECTORS = frozenset({
    "alloc", "init", "new", "copy", "mutableCopy", "retain", "release",
    "autorelease", "dealloc", "load", "self", "class",
})  # fmt: skip

# A leading `get` before a camel word: `getTitle` -> `Title`, but `get` alone is left as-is.
_GET_PREFIX = re.compile(r"^get(?=[A-Z])")
_IDENTIFIER = re.compile(r"^[A-Za-z_]\w*$")


def rename_getters_setters_during_decompilation(cfunc: cfunc_t) -> bool:
    """
    Rename default-named locals in `cfunc` from the getters/setters that touch them.

    For use inside a decompilation event (e.g. a `maturity` hook): the renames are written
    through the saved-settings fast path and patched onto the live `lvar_t`s, so no extra
    decompilation is triggered.

    Args:
        cfunc: The function's in-flight decompilation.

    Returns:
        `True` if at least one local was renamed.
    """
    func_lvars = cfunc.get_lvars()
    candidates = _collect_candidates(cfunc, func_lvars)
    if not candidates:
        return False

    modifications = _build_modifications(func_lvars, candidates)
    if not modifications:
        return False

    renamed = lvars.perform_lvar_modifications_during_decompilation(cfunc.entry_ea, func_lvars, modifications)
    if renamed and config.debug:
        summary = ", ".join(f"{old} -> {mod.name}" for old, mod in modifications.items())
        print(f"[Debug] objc-getter-setter: {memory.name_from_ea(cfunc.entry_ea)}: {summary}")
    return renamed


def _collect_candidates(cfunc: cfunc_t, func_lvars: lvars_t) -> dict[int, str]:
    """
    Walk the ctree and map each renamable local's index to its derived base name.

    Dedupes by variable index (the first getter/setter that names a variable wins) and
    skips variables that no longer carry a default `vN` name.
    """
    candidates: dict[int, str] = {}

    def consider(match: tuple[int, str] | None) -> None:
        if match is None:
            return
        var_index, base_name = match
        if var_index in candidates or var_index >= func_lvars.size():
            return
        if _DEFAULT_LVAR_NAME.match(func_lvars[var_index].name):
            candidates[var_index] = base_name

    class Visitor(ctree_visitor_t):
        def __init__(self) -> None:
            super().__init__(ida_hexrays.CV_PARENTS)

        def visit_expr(self, e: cexpr_t) -> int:
            if e.op == ida_hexrays.cot_call and _is_msgsend_call(e):
                consider(_getter_match(e, self.parents))
                consider(_setter_match(e))
            return 0

    Visitor().apply_to(cfunc.body, None)
    return candidates


def _getter_match(call: cexpr_t, parents: ctree_items_t) -> tuple[int, str] | None:
    """A getter `var = [recv sel]` yields `(assigned var index, name)`, else `None`."""
    if call.a.size() != 2:  # receiver + selector, no real arguments
        return None
    selector = _selector_of(call)
    if selector is None:
        return None
    name = _getter_name(selector)
    target = citem.assignment_target(parents) if name is not None else None
    return (target.v.idx, name) if name is not None and target is not None else None


def _setter_match(call: cexpr_t) -> tuple[int, str] | None:
    """A setter `[recv setSel:var]` yields `(passed var index, name)`, else `None`."""
    if call.a.size() != 3:  # receiver + selector + one value argument
        return None
    selector = _selector_of(call)
    if selector is None:
        return None
    name = _setter_name(selector)
    value = cexpr.strip_casts(call.a[2])
    return (value.v.idx, name) if name is not None and value.op == ida_hexrays.cot_var else None


def _build_modifications(func_lvars: lvars_t, candidates: dict[int, str]) -> dict[str, VariableModification]:
    """Turn `{var_index: base_name}` into `{current_name: modification}`, de-duplicating names."""
    taken = {
        func_lvars[i].name
        for i in range(func_lvars.size())
        if func_lvars[i].name and not _DEFAULT_LVAR_NAME.match(func_lvars[i].name)
    }
    modifications: dict[str, VariableModification] = {}
    for var_index, base_name in candidates.items():
        name = naming.unique_name(base_name, taken)
        taken.add(name)
        modifications[func_lvars[var_index].name] = VariableModification(name=name)
    return modifications


def _is_msgsend_call(call: cexpr_t) -> bool:
    """Whether `call`'s callee is an Obj-C dispatch (helper, resolved method, or selector stub)."""
    name = cexpr.get_call_name(call)
    return name is not None and (name in objc.MSGSEND_NAMES or objc.is_msgsend_stub(name) or objc.is_objc_method(name))


def _selector_of(call: cexpr_t) -> str | None:
    """
    The selector of a dispatch call — its second argument — however IDA spells it.

    Usually an inlined string literal (`cot_str`), but when the same selector is also needed
    as a `SEL` value nearby (e.g. a `respondsToSelector:` guard) IDA keeps the argument as a
    `&sel_<name>` reference into `__objc_selrefs` (`cot_obj`) instead; read the selector
    string it points to in that case.

    Returns:
        The selector string, or `None` if the call has no selector argument or it is neither
        an inline string nor a resolvable selector reference.
    """
    if call.a is None or call.a.size() < 2:
        return None
    selector_arg = cexpr.strip_casts(call.a[1])
    if selector_arg.op == ida_hexrays.cot_str:
        return selector_arg.string
    if selector_arg.op == ida_hexrays.cot_obj:
        return memory.str_from_ea(selector_arg.obj_ea)
    return None


def _getter_name(selector: str) -> str | None:
    """Derive a snake_case name from a zero-argument getter selector, or `None` to skip it."""
    if not selector or ":" in selector or selector in _NON_GETTER_SELECTORS:
        return None
    return _to_snake_identifier(_GET_PREFIX.sub("", selector))


def _setter_name(selector: str) -> str | None:
    """Derive a snake_case name from a single-argument `setFoo:` selector, or `None` to skip it."""
    if not selector.startswith("set") or not selector.endswith(":") or selector.count(":") != 1:
        return None
    return _to_snake_identifier(selector[3:-1])


def _to_snake_identifier(camel: str) -> str | None:
    """Lower `camel` to snake_case, or `None` if the result is not a usable identifier."""
    if not camel:
        return None
    snake = naming.camel_to_snake(camel)
    return snake if _IDENTIFIER.match(snake) else None
