"""
Pseudocode sugar that rewrites ``objc_msgSend`` calls into Obj-C bracket syntax.

A Hex-Rays ``func_printed`` hook post-processes the tokenized pseudocode, rewriting
``objc_msgSend(recv, "sel:", a, b)`` into the lighter ``[recv sel:](a, b)``, doing the
same for the Obj-C runtime fast-paths (``objc_alloc``, ``objc_opt_self``, … — see
``objc_opt``), and folding wrapped continuation lines back together where they now fit.
"""

__all__ = ["objc_msgsend_hexrays_hooks_t"]

from dataclasses import replace

from ida_hexrays import Hexrays_Hooks, cfunc_t, vdui_t
from ida_kernwin import simpleline_t
from ida_pro import strvec_t
from idahelper.pseudocode import Anchor, Color, Line, Token

from .selectors import handle_selector_double_click, handle_selector_xref, make_selector_token, register_selectors
from .tokens import MAX_REWRITES, find_callee, open_paren_after, split_args

# IDA renders every message send the same way regardless of dispatch (bare
# `objc_msgSend`, a `j_`-thunk, or a selector stub `_objc_msgSend$foo`) — always
# as `objc_msgSend(receiver, "selector", ...)`. These are the callee spellings we
# rewrite; `objc_msgSendSuper2` etc. are deliberately excluded.
MSGSEND_NAMES = frozenset({"objc_msgSend", "_objc_msgSend", "j_objc_msgSend", "j__objc_msgSend"})

# Wrapped continuation lines are merged back together as long as the result stays
# within this many visible columns (Hex-Rays' line width is not exposed via the
# SDK, so this mirrors its common default).
MAX_LINE_LENGTH = 120


class objc_msgsend_hexrays_hooks_t(Hexrays_Hooks):
    """
    Rewrite ``objc_msgSend(recv, "sel:", a, b)`` into the sugar ``[recv sel:](a, b)``.

    This is a pure text post-process over the tokenized pseudocode: it keeps the
    receiver and argument tokens *verbatim* (preserving their colors and ctree
    anchors so navigation keeps working) and only rewrites the structural tokens.
    The synthesized selector token is anchored to the selector argument's ctree
    item, so hovering it shows the selector (not the receiver); double-clicking and
    pressing ``x`` over it are handled uniformly with the runtime fast-paths by
    ``selectors``. As a final step it also merges wrapped continuation lines back
    together where they now fit (see :func:`merge_wrapped_lines`).
    """

    def func_printed(self, cfunc: cfunc_t) -> int:
        """
        Apply the bracket rewrite, runtime-fast-path sugar, and line-merge to the pseudocode.
        """
        # Imported lazily so a hot `reload()` always binds the freshly reloaded
        # `objc_opt` rather than a stale reference captured at import time.
        from .objc_opt import rewrite_opt_calls

        # Resolve the pseudocode once: `func_printed` may run mid-build and a second
        # `get_pseudocode()` can return a different strvec. Operate on the whole
        # function as one tagged blob so calls wrapped across lines are handled too.
        ps = cfunc.get_pseudocode()
        line = Line.parse("\n".join(ps[i].line for i in range(ps.size())))
        selectors = rewrite(line.tokens)
        opt_selectors = rewrite_opt_calls(line.tokens)
        # Register the message-send and runtime-fast-path selectors together so
        # double-click / `x` work uniformly across both. The two call kinds anchor to
        # different ctree items, so their indices never collide.
        merged_selectors = {**(selectors or {}), **(opt_selectors or {})}
        if merged_selectors:
            register_selectors(cfunc.entry_ea, merged_selectors)
        tagged_lines = line.to_tagged().split("\n")
        merged = merge_wrapped_lines(tagged_lines)
        if not merged_selectors and len(merged) == len(tagged_lines):
            return 0  # neither a rewrite, runtime sugar, nor line merge changed anything
        write_back(ps, merged)
        return 0

    def double_click(self, vu: vdui_t, shift_state: int) -> int:
        """
        Forward a double-click on a rewritten selector to IDA's selector-jump action.
        """
        return handle_selector_double_click(vu)

    def keyboard(self, vu: vdui_t, key_code: int, shift_state: int) -> int:
        """
        List a rewritten selector's call sites when ``x`` is pressed over it.
        """
        return handle_selector_xref(vu, key_code, shift_state)


def rewrite(tokens: list[Token]) -> dict[int, str] | None:
    """
    Rewrite every ``objc_msgSend`` call in ``tokens`` in place.

    Nested calls are handled because inner calls are kept verbatim inside the
    receiver/arguments and re-scanned.

    Args:
        tokens: The function's pseudocode tokens, mutated in place.

    Returns:
        A map of each selector's ctree-item index to its string, or ``None`` when
        nothing was rewritten.
    """
    selectors: dict[int, str] = {}
    pos = 0
    for _ in range(MAX_REWRITES):
        pos = find_callee(tokens, pos, MSGSEND_NAMES)
        if pos is None:
            break
        open_paren = open_paren_after(tokens, pos)
        if open_paren is None:
            pos += 1
            continue
        args, close = split_args(tokens, open_paren)
        if args is None or len(args) < 2:
            pos += 1
            continue
        built = _build_call(tokens, args[0], args[1], args[2:])
        if built is None:
            pos += 1
            continue
        new_tokens, selector = built
        tokens[pos : close + 1] = new_tokens
        selectors[selector[0]] = selector[1]
        # Re-scan from `pos`: `tokens[pos]` is now `[`, and any nested call kept
        # verbatim in the receiver/arguments lies further on and is picked up next.
    return selectors or None


def _build_call(
    tokens: list[Token],
    receiver: tuple[int, int],
    selector: tuple[int, int],
    rest: list[tuple[int, int]],
) -> tuple[list[Token], tuple[int, str]] | None:
    """
    Build the ``[recv sel](args)`` token list for a rewritten message send.

    Args:
        tokens: The pseudocode tokens the spans index into.
        receiver: Inclusive ``(start, end)`` token span of the receiver argument.
        selector: Inclusive ``(start, end)`` token span of the selector argument.
        rest: Inclusive token spans of the remaining call arguments.

    Returns:
        A ``(tokens, (index, selector))`` pair — the rewritten token list plus the
        selector's ctree-item index and string — or ``None`` if arg 2 is not a
        literal selector. The call parentheses are always emitted, so a zero-argument
        selector still reads as ``[recv sel]()``.
    """
    parsed = _selector_of(tokens, selector)
    if parsed is None:
        return None
    text, anchor = parsed

    out: list[Token] = [Token("[", Color.SYMBOL)]
    out += tokens[receiver[0] : receiver[1] + 1]
    out.append(Token(" "))
    # Anchor the selector name to the selector's own ctree item, so hovering /
    # double-clicking it resolves to the selector — not the receiver.
    out.append(make_selector_token(text, anchor))
    out.append(Token("]", Color.SYMBOL))
    # Always emit the call parentheses, so a zero-argument selector still reads as
    # a call: ``[recv sel]()`` rather than the ambiguous ``[recv sel]``.
    out.append(Token("(", Color.SYMBOL))
    if rest:
        out += tokens[rest[0][0] : rest[-1][1] + 1]
    out.append(Token(")", Color.SYMBOL))
    return out, (anchor.index, text)


def _selector_of(tokens: list[Token], span: tuple[int, int]) -> tuple[str, Anchor] | None:
    """
    Extract ``(selector, anchor)`` from an argument span, or ``None`` if it is not a literal.
    """
    start, end = span
    sub = tokens[start : end + 1]
    visible = "".join(token.text for token in sub).strip()
    if len(visible) < 2 or visible[0] != '"' or visible[-1] != '"':
        return None
    selector = visible[1:-1]
    anchor = next((token.anchor for token in sub if token.anchor is not None), None)
    if not selector or anchor is None:
        return None
    return selector, anchor


def write_back(ps: strvec_t, new_lines: list[str]) -> None:
    """
    Replace the pseudocode lines with ``new_lines`` in place.

    Existing ``simpleline_t`` objects are reused so their metadata survives. The
    transform never adds lines, so any surplus lines are erased.

    Args:
        ps: The function's pseudocode line vector, modified in place.
        new_lines: The replacement tagged lines, at most as many as ``ps`` holds.
    """
    surplus: list[simpleline_t] = []
    for i, line in enumerate(ps):
        line: simpleline_t
        if i < len(new_lines):
            line.line = new_lines[i]
        else:
            surplus.append(line)
    for line in reversed(surplus):
        ps.erase(line)


def merge_wrapped_lines(tagged_lines: list[str]) -> list[str]:
    """
    Fold wrapped continuation lines back together where the result still fits.

    A line is a *continuation* when the running ``()``/``[]`` nesting depth at its
    start is greater than zero — i.e. it belongs to an unclosed call/subscript on a
    previous line. Such a line is appended to the line above it (with one separating
    space, or none after an opener / before a closer) as long as the joined visible
    text stays within :data:`MAX_LINE_LENGTH`. Statement boundaries sit at depth 0
    and are never merged, so distinct statements stay on their own lines.
    """
    merged: list[Line] = []
    depth = 0
    for tagged in tagged_lines:
        line = Line.parse(tagged)
        at_continuation = depth > 0
        depth += _bracket_balance(line)
        if merged and at_continuation and _fits(merged[-1], line):
            _append_continuation(merged[-1], line)
        else:
            merged.append(line)
    return [line.to_tagged() for line in merged]


def _bracket_balance(line: Line) -> int:
    """
    The net ``()``/``[]`` nesting a line opens (``{}`` and string contents excluded).
    """
    depth = 0
    for token in line.tokens:
        if token.color == Color.SYMBOL:
            depth += token.text.count("(") + token.text.count("[")
            depth -= token.text.count(")") + token.text.count("]")
    return depth


def _fits(target: Line, cont: Line) -> bool:
    """
    Whether ``cont`` can be appended to ``target`` without exceeding the width.
    """
    body = cont.text.strip()
    if not body:
        return True
    space = 0 if _abuts(target.text, body) else 1
    return len(target.text) + space + len(body) <= MAX_LINE_LENGTH


def _abuts(target_text: str, cont_text: str) -> bool:
    """
    Whether the continuation should join with no separating space.
    """
    return target_text[-1:] in "([" or cont_text[:1] in ")];,."


def _append_continuation(target: Line, cont: Line) -> None:
    """
    Append ``cont``'s tokens to ``target`` with exactly one separating space.

    Both edges are normalized — the target's trailing whitespace and the
    continuation's leading indentation are trimmed — so the join never produces a
    double space or a stray space before a closer.
    """
    body = _lstrip_indent(cont.tokens)
    text = "".join(token.text for token in body)
    if not text:
        return
    _rstrip_whitespace(target.tokens)
    if not _abuts(target.text, text):
        target.tokens.append(Token(" "))
    target.tokens.extend(body)


def _rstrip_whitespace(tokens: list[Token]) -> None:
    """
    Trim trailing whitespace from a line's tokens, in place (keeps a trailing anchor).
    """
    while tokens:
        last = tokens[-1]
        if last.anchor is not None and not last.text:
            break
        stripped = last.text.rstrip()
        if stripped == last.text:
            break
        if stripped:
            tokens[-1] = replace(last, text=stripped)
            break
        tokens.pop()


def _lstrip_indent(tokens: list[Token]) -> list[Token]:
    """
    Drop a continuation line's leading indentation, keeping its anchor marks.
    """
    anchors: list[Token] = []
    i = 0
    while i < len(tokens):
        token = tokens[i]
        if token.anchor is not None and not token.text:
            anchors.append(token)
        elif not (token.color is None and not token.inverse and not token.text.strip()):
            break
        i += 1
    rest = tokens[i:]
    # Indentation may live *inside* a colored token rather than in a standalone
    # whitespace token (e.g. a wrapped `REG` parameter declaration), so also trim
    # leading whitespace from the first content token's text.
    if rest and rest[0].text[:1].isspace():
        rest = [replace(rest[0], text=rest[0].text.lstrip()), *rest[1:]]
    return anchors + rest
