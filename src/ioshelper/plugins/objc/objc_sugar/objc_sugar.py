"""
Pseudocode sugar that strips redundant selector/class arguments from Obj-C calls.

A Hex-Rays ``func_printed`` hook deletes the selector-string argument (and, for class
methods, the ``&OBJC_CLASS___…`` receiver) that merely echo an already-rendered Obj-C
method name, collapsing any line left holding only closers back into the call above.
"""

__all__ = ["objc_selector_hexrays_hooks_t"]

import ida_hexrays
from ida_hexrays import Hexrays_Hooks, carg_t, carglist_t, cexpr_t, cfunc_t, citem_t
from idahelper import memory, objc
from idahelper.ast import cexpr
from idahelper.pseudocode import Anchor, Color, Line, Pseudocode, Section, Token

from .tokens import drop_trailing_comma

# Object-C class refs are rendered as ``OBJC_CLASS___<Name>``.
OBJC_CLASS_PREFIX = "OBJC_CLASS___"
# Visible characters a line may consist of (besides whitespace) and still be merged
# upward after its selector/class argument was removed — closers and separators.
CLOSER_CHARS = frozenset(")]};,")


class objc_selector_hexrays_hooks_t(Hexrays_Hooks):
    """
    Strip the redundant selector/class arguments from rendered Obj-C method calls.

    When IDA prints an Obj-C method call such as ``-[Foo bar:](recv, "bar:", x)``, the
    selector string (and, for class methods, the ``&OBJC_CLASS___Foo`` receiver) just
    echoes the method name. This ``func_printed`` hook deletes those tokens from the
    tokenized pseudocode, leaving the cleaner ``-[Foo bar:](recv, x)``.
    """

    def func_printed(self, cfunc: cfunc_t) -> int:  # noqa: C901
        """
        Collect the redundant selector/class arguments and strip them from the text.
        """
        selectors_to_remove: dict[int, str] = {}  # obj_id -> selector
        classes_to_remove: set[int] = set()  # obj_id
        index_to_sel: dict[int, str] = {}  # index, selector
        class_indices_to_remove: set[int] = set()  # index

        for i, call_item in enumerate(cfunc.treeitems):
            call_item: citem_t
            # Get the index of the selector/class AST element
            if call_item.obj_id in selectors_to_remove:
                index_to_sel[i] = selectors_to_remove.pop(call_item.obj_id)
            elif call_item.obj_id in classes_to_remove:
                class_indices_to_remove.add(i)
                classes_to_remove.remove(call_item.obj_id)

            elif call_item.op == ida_hexrays.cot_call:
                call_expr: cexpr_t = call_item.cexpr

                # 1. Check if the function name looks like an Obj-C method
                call_func_name = cexpr.get_call_name(call_expr)
                if call_func_name is None or not objc.is_objc_method(call_func_name):
                    continue

                # 2. Collect selector from arglist
                arglist: carglist_t = call_expr.a
                if len(arglist) < 2:
                    print("[Error]: Obj-C method call with less than 2 arguments:", call_expr.dstr())
                    continue
                sel_arg: carg_t = arglist[1]
                if sel_arg.op == ida_hexrays.cot_str:
                    selectors_to_remove[sel_arg.obj_id] = sel_arg.string
                elif sel_arg.op == ida_hexrays.cot_obj and (sel := memory.str_from_ea(sel_arg.obj_ea)) is not None:
                    selectors_to_remove[sel_arg.obj_id] = sel
                else:
                    print("[Error]: Obj-C method call with non-string selector:", call_expr.dstr())
                    continue

                # 3. Check if the function is a class method
                if objc.is_objc_static_method(call_func_name):
                    # 4. Check if the class name is a ref to obj
                    class_arg: carg_t = arglist[0]
                    if class_arg.op != ida_hexrays.cot_ref or class_arg.x.op != ida_hexrays.cot_obj:
                        print("[Error]: Obj-C class method with unsupported class", call_expr.dstr())
                        continue
                    # 5. Collect the class name
                    classes_to_remove.add(class_arg.obj_id)

        if selectors_to_remove or classes_to_remove:
            print("[Error]: unmatched Obj-C selectors in the function: ", hex(cfunc.entry_ea))
        elif index_to_sel:
            modify_text(cfunc, index_to_sel, class_indices_to_remove)
        return 0


def modify_text(cfunc: cfunc_t, index_to_sel: dict[int, str], class_indices_to_remove: set[int]) -> None:
    """
    Remove the redundant selector/class arguments from the rendered pseudocode.

    Each code line is parsed into colored tokens; the argument tokens whose ctree
    anchor matches ``index_to_sel`` / ``class_indices_to_remove`` are deleted along
    with their separating comma. A line that is left empty is dropped, and a line
    left holding only closers (e.g. ``));``) is merged up into the nearest
    surviving line — so a wrapped call collapses back to balanced text.
    """
    if not index_to_sel and not class_indices_to_remove:
        return

    # Resolve the pseudocode once: `func_printed` may run mid-build, and calling
    # `get_pseudocode()` again (e.g. via `Pseudocode.from_cfunc`) can hand back a
    # different strvec — so parse and write back through this single object.
    ps = cfunc.get_pseudocode()
    pc = Pseudocode.from_lines([Line.parse(ps[i].line) for i in range(len(ps))], cfunc.hdrlines)
    dirty: set[int] = set()
    to_erase: list[int] = []
    survivors: list[int] = []  # kept code-line indices, newest last (merge targets)

    for i, line in enumerate(pc.lines):
        if pc.section_of(i) != Section.CODE:
            continue
        if not _remove_objc_args(line, index_to_sel, class_indices_to_remove):
            survivors.append(i)
            continue

        dirty.add(i)
        stripped = line.text.strip()
        if not stripped:
            to_erase.append(i)
        elif survivors and all(ch in CLOSER_CHARS for ch in stripped):
            target = survivors[-1]
            _merge_into(pc.lines[target], line)
            dirty.add(target)
            dirty.discard(i)
            to_erase.append(i)
        else:
            survivors.append(i)

    erase_set = set(to_erase)
    for i in dirty - erase_set:
        ps[i].line = pc.lines[i].to_tagged()
    # `ps.erase` is positional, so erase high indices first to keep the rest valid.
    for i in sorted(to_erase, reverse=True):
        ps.erase(ps[i])


def _remove_objc_args(line: Line, index_to_sel: dict[int, str], class_indices_to_remove: set[int]) -> bool:
    """
    Delete matching selector/class argument tokens from ``line``.

    Args:
        line: The parsed pseudocode line, mutated in place.
        index_to_sel: Selector ctree-item index -> selector string; matched entries
            are consumed.
        class_indices_to_remove: ``&OBJC_CLASS___`` ref indices to strip; matched
            entries are consumed.

    Returns:
        Whether any token was removed from ``line``.
    """
    tokens = line.tokens
    owners = _owning_anchors(tokens)
    to_delete: set[int] = set()

    for i, token in enumerate(tokens):
        anchor = owners[i]
        if anchor is None:
            continue
        if token.color == Color.LOCNAME and anchor.index in index_to_sel:
            if token.text.strip('"') != index_to_sel[anchor.index]:
                continue  # a different string happens to share the anchor — leave it
            del index_to_sel[anchor.index]
            _mark_selector(tokens, i, anchor.index, to_delete)
        elif token.color in (Color.DEMNAME, Color.IMPNAME) and token.text.startswith(OBJC_CLASS_PREFIX):
            ref_index = anchor.index - 1  # the `&` ref is the item before its object
            if ref_index in class_indices_to_remove:
                class_indices_to_remove.discard(ref_index)
                _mark_class(tokens, i, anchor.index, to_delete)

    if not to_delete:
        return False
    line.tokens = [token for j, token in enumerate(tokens) if j not in to_delete]
    return True


def _owning_anchors(tokens: list[Token]) -> list[Anchor | None]:
    """
    For each token, the nearest anchor at or before it (the ctree item it belongs to).
    """
    owners: list[Anchor | None] = []
    active: Anchor | None = None
    for token in tokens:
        if token.anchor is not None:
            active = token.anchor
        owners.append(active)
    return owners


def _mark_selector(tokens: list[Token], value: int, index: int, to_delete: set[int]) -> None:
    """
    Mark a selector string token, its anchors / opening quote, and a separating comma.
    """
    to_delete.add(value)
    start = value
    while start > 0 and _is_selector_head(tokens[start - 1], index):
        start -= 1
        to_delete.add(start)
    _mark_comma(tokens, start, value, to_delete)


def _mark_class(tokens: list[Token], value: int, obj_index: int, to_delete: set[int]) -> None:
    """
    Mark an ``OBJC_CLASS___`` token, its ``&`` ref / anchors, and a separating comma.
    """
    to_delete.add(value)
    start = value
    while start > 0 and _is_class_head(tokens[start - 1], obj_index):
        start -= 1
        to_delete.add(start)
    _mark_comma(tokens, start, value, to_delete)


def _is_selector_head(token: Token, index: int) -> bool:
    """
    A token that precedes the selector string and belongs to it (its anchor or opening quote).
    """
    if token.anchor is not None:
        return token.anchor.index == index
    return token.is_symbol('"')


def _is_class_head(token: Token, obj_index: int) -> bool:
    """
    A token that precedes the ``OBJC_CLASS___`` name and belongs to it (its anchors or the ``&``).
    """
    if token.anchor is not None:
        return token.anchor.index in (obj_index, obj_index - 1)
    return token.is_symbol("&")


def _mark_comma(tokens: list[Token], start: int, end: int, to_delete: set[int]) -> None:
    """
    Mark the comma separating the argument spanning ``[start, end]`` from its siblings.

    Prefers the trailing comma (``arg, …``); falls back to the leading comma when the
    argument is last (``…, arg``). The accompanying space is removed with the comma.
    """
    after = end + 1
    if after < len(tokens) and tokens[after].is_symbol(","):
        to_delete.add(after)
        if after + 1 < len(tokens) and tokens[after + 1].is_blank:
            to_delete.add(after + 1)
        return

    before = start - 1
    space = None
    if before >= 0 and tokens[before].is_blank:
        space, before = before, before - 1
    if before >= 0 and tokens[before].is_symbol(","):
        to_delete.add(before)
        if space is not None:
            to_delete.add(space)


def _merge_into(target: Line, source: Line) -> None:
    """
    Append ``source``'s closers to ``target``, dropping a now-dangling trailing comma.
    """
    if target.text.rstrip().endswith(","):
        drop_trailing_comma(target.tokens)
    target.tokens.extend(_lstrip_tokens(source.tokens))


def _lstrip_tokens(tokens: list[Token]) -> list[Token]:
    """
    Drop leading indentation and position anchors so merged closers sit flush.
    """
    i = 0
    while i < len(tokens) and (tokens[i].anchor is not None or tokens[i].is_blank):
        i += 1
    return tokens[i:]
