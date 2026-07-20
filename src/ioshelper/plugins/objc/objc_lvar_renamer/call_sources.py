"""
Name sources fed by one ctree walk: getters and callee keyword arguments.

Two message-send shapes carry an obvious name for the variable they touch:

* a **getter** assigns a property to a variable -- `v5 = [obj title]` / `v5 = [obj getTitle]`
  names `v5` `title`;
* a **callee keyword argument** passes a variable at a keyword position -- `[obj setTitle:v5]`
  names `v5` `title`, `[view insertSubview:v3 atIndex:v4]` names `v3` `subview` and `v4`
  `at_index`. The first keyword piece carries no keyword of its own, so its name is guessed
  from the same verb/preposition patterns as the args source (`addObserver:` -> `observer`).

The selector is the name source; the class is not consulted. Names are lowered to
snake_case and only variables still holding a hex-rays default `aN`/`vN` name are
candidates, so user renames are never clobbered.

Recognition works on the raw ctree, so it is independent of how IDA spells the call
(`objc_msgSend(recv, "sel", …)`, a resolved `-[Cls sel]`, or an `_objc_msgSend$sel`
stub): in every case the selector is the call's second argument (a string literal) and
the real arguments follow it.
"""

__all__ = ["collect_call_candidates"]

from collections.abc import Iterator

import ida_hexrays
from ida_hexrays import cexpr_t, cfunc_t, ctree_items_t, ctree_visitor_t, lvars_t
from idahelper import memory, objc
from idahelper.ast import cexpr, citem

from .heuristics import DEFAULT_LVAR_NAME, getter_name, guess_implicit_arg_name, to_snake_identifier


def collect_call_candidates(
    decompiled: cfunc_t, func_lvars: lvars_t, *, want_getters: bool, want_callee_args: bool
) -> tuple[dict[str, str], dict[str, str]]:
    """
    Walk the ctree once and collect rename candidates from the enabled call sources.

    Dedupes per source by variable (the first call that names a variable wins) and skips
    variables that no longer carry a default `aN`/`vN` name.

    Args:
        decompiled: The function's in-flight decompilation.
        func_lvars: The decompilation's lvars (`decompiled.get_lvars()`).
        want_getters: Collect getter candidates.
        want_callee_args: Collect callee keyword-argument candidates.

    Returns:
        Two `{current lvar name: proposed base name}` mappings: getter candidates and
        callee keyword-argument candidates.
    """
    visitor = _CallCandidateVisitor(func_lvars, want_getters=want_getters, want_callee_args=want_callee_args)
    visitor.apply_to(decompiled.body, None)
    return visitor.getters, visitor.callee_args


class _CallCandidateVisitor(ctree_visitor_t):
    """
    Collect getter and callee keyword-argument candidates in one ctree pass.

    Attributes:
        getters: Getter candidates, `{current lvar name: proposed base name}`.
        callee_args: Callee keyword-argument candidates, same shape.
    """

    def __init__(self, func_lvars: lvars_t, *, want_getters: bool, want_callee_args: bool) -> None:
        super().__init__(ida_hexrays.CV_PARENTS)
        self._func_lvars = func_lvars
        self._want_getters = want_getters
        self._want_callee_args = want_callee_args
        self.getters: dict[str, str] = {}
        self.callee_args: dict[str, str] = {}

    def visit_expr(self, e: cexpr_t) -> int:
        if e.op != ida_hexrays.cot_call or not _is_msgsend_call(e):
            return 0
        selector = _selector_of(e)
        if selector is None:
            return 0
        if self._want_getters:
            self._consider(self.getters, _getter_match(e, selector, self.parents))
        if self._want_callee_args:
            for match in _callee_arg_matches(e, selector):
                self._consider(self.callee_args, match)
        return 0

    def _consider(self, into: dict[str, str], match: tuple[int, str] | None) -> None:
        """Record `match` into `into` unless its variable is out of range, taken, or non-default."""
        if match is None:
            return
        var_index, base_name = match
        if var_index >= self._func_lvars.size():
            return
        current = self._func_lvars[var_index].name
        if current not in into and DEFAULT_LVAR_NAME.match(current):
            into[current] = base_name


def _getter_match(call: cexpr_t, selector: str, parents: ctree_items_t) -> tuple[int, str] | None:
    """A getter `var = [recv sel]` yields `(assigned var index, base name)`, else `None`."""
    if call.a.size() != 2:  # receiver + selector, no real arguments
        return None
    name = getter_name(selector)
    if name is None:
        return None
    target = citem.assignment_target(parents)
    return (target.v.idx, name) if target is not None else None


def _callee_arg_matches(call: cexpr_t, selector: str) -> Iterator[tuple[int, str]]:
    """
    Yield `(passed var index, base name)` for each keyword argument of `call` passing a variable.

    Only calls whose argument count exactly matches the selector's keyword count are
    considered (receiver + selector + one value per keyword), so vararg selectors like
    `stringWithFormat:` and calls with a mis-recovered argument count are skipped whole.
    """
    keyword_pieces = selector.split(":")
    value_count = len(keyword_pieces) - 1
    if value_count < 1:  # no colon -> not a keyword selector
        return
    if call.a.size() != value_count + 2:  # receiver + selector + one value per keyword
        return
    for pos in range(value_count):
        value = cexpr.strip_casts(call.a[pos + 2])
        if value.op != ida_hexrays.cot_var:
            continue
        name = _keyword_arg_name(keyword_pieces, pos)
        if name is not None:
            yield value.v.idx, name


def _keyword_arg_name(keyword_pieces: list[str], pos: int) -> str | None:
    """
    Derive a snake_case name for the argument at keyword position `pos`, or `None` to skip it.

    The first piece is the method name itself, so its argument is guessed from the shared
    verb/preposition patterns (`setTitle:` -> `title`); later pieces name their argument
    directly (`atIndex:` -> `at_index`).
    """
    if pos == 0:
        guess = guess_implicit_arg_name(keyword_pieces)
        return to_snake_identifier(guess) if guess is not None else None
    return to_snake_identifier(keyword_pieces[pos])


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
