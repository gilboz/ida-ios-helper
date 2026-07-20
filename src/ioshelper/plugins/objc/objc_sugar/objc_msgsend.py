"""
Pseudocode sugar that rewrites Obj-C calls into bracket message-send syntax.

A Hex-Rays `func_printed` hook post-processes the tokenized pseudocode:

* `objc_msgSend(recv, "sel:", a, b)` becomes the lighter `[recv sel:](a, b)`;
* the Obj-C runtime fast-paths (`objc_alloc`, `objc_opt_self`, …) become message
  sends too — see `objc_opt`;
* a no-argument send drops its lone trailing selector colon (`init` not `init:`);
* wrapped continuation lines are folded back together where they now fit.
"""

__all__ = ["objc_msgsend_hexrays_hooks_t"]

from dataclasses import replace

from ida_hexrays import Hexrays_Hooks, cfunc_t, vdui_t
from ida_kernwin import simpleline_t
from ida_pro import strvec_t

# IDA renders every message send the same way regardless of dispatch (bare
# `objc_msgSend`, a `j_`-thunk, or a selector stub `_objc_msgSend$foo`) — always
# as `objc_msgSend(receiver, "selector", ...)`. `MSGSEND_NAMES` holds the callee
# spellings we rewrite; `objc_msgSendSuper2` etc. are deliberately excluded.
from idahelper.objc import MSGSEND_NAMES
from idahelper.pseudocode import Anchor, AnchorKind, Color, Line, Token

from .selectors import handle_selector_double_click, handle_selector_xref, make_selector_token, register_selectors
from .tokens import MAX_REWRITES, drop_trailing_comma, find_callee, open_paren_after, split_args

# Wrapped continuation lines are merged back together as long as the result stays
# within this many visible columns (Hex-Rays' line width is not exposed via the
# SDK, so this mirrors its common default).
MAX_LINE_LENGTH = 120


class objc_msgsend_hexrays_hooks_t(Hexrays_Hooks):
    """
    Rewrite `objc_msgSend(recv, "sel:", a, b)` into the sugar `[recv sel:](a, b)`.

    This is a pure text post-process over the tokenized pseudocode: it keeps the
    receiver and argument tokens *verbatim* (preserving their colors and ctree
    anchors so navigation keeps working) and only rewrites the structural tokens.
    The synthesized selector token is anchored to the selector argument's ctree
    item, so hovering it shows the selector (not the receiver); double-clicking and
    pressing `x` over it are handled uniformly with the runtime fast-paths by
    `selectors`. As a final step it also merges wrapped continuation lines back
    together where they now fit (see `merge_wrapped_lines`).
    """

    def func_printed(self, cfunc: cfunc_t) -> int:
        """Apply the bracket rewrite, zero-arg colon cleanup, and line-merge to the pseudocode."""
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
        colons_stripped = _strip_zero_arg_colons(line.tokens)
        # Register the message-send and runtime-fast-path selectors together so
        # double-click / `x` work uniformly across both. The two call kinds anchor to
        # different ctree items, so their indices never collide.
        merged_selectors = {**(selectors or {}), **(opt_selectors or {})}
        if merged_selectors:
            register_selectors(cfunc.entry_ea, merged_selectors)
        tagged_lines = line.to_tagged().split("\n")
        merged = merge_wrapped_lines(tagged_lines, cfunc.hdrlines)
        if not merged_selectors and not colons_stripped and len(merged) == len(tagged_lines):
            return 0  # nothing changed: no rewrite, no runtime sugar, no colon cleanup, no merge
        write_back(ps, merged)
        return 0

    def double_click(self, vu: vdui_t, shift_state: int) -> int:
        """Forward a double-click on a rewritten selector to IDA's selector-jump action."""
        return handle_selector_double_click(vu)

    def keyboard(self, vu: vdui_t, key_code: int, shift_state: int) -> int:
        """List a rewritten selector's call sites when `x` is pressed over it."""
        return handle_selector_xref(vu, key_code, shift_state)


def rewrite(tokens: list[Token]) -> dict[int, str] | None:
    """
    Rewrite every `objc_msgSend` call in `tokens` in place.

    Nested calls are handled because inner calls are kept verbatim inside the
    receiver/arguments and re-scanned.

    Args:
        tokens: The function's pseudocode tokens, mutated in place.

    Returns:
        A map of each selector's ctree-item index to its string, or `None` when
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
    Build the `[recv sel](args)` token list for a rewritten message send.

    Args:
        tokens: The pseudocode tokens the spans index into.
        receiver: Inclusive `(start, end)` token span of the receiver argument.
        selector: Inclusive `(start, end)` token span of the selector argument.
        rest: Inclusive token spans of the remaining call arguments.

    Returns:
        A `(tokens, (index, selector))` pair — the rewritten token list plus the
        selector's ctree-item index and string — or `None` if arg 2 is not a
        literal selector. The call parentheses are always emitted, so a zero-argument
        selector still reads as `[recv sel]()`.
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
    # a call: `[recv sel]()` rather than the ambiguous `[recv sel]`.
    out.append(Token("(", Color.SYMBOL))
    if rest:
        out += tokens[rest[0][0] : rest[-1][1] + 1]
    out.append(Token(")", Color.SYMBOL))
    return out, (anchor.index, text)


def _selector_of(tokens: list[Token], span: tuple[int, int]) -> tuple[str, Anchor] | None:
    """Extract `(selector, anchor)` from an argument span, or `None` if it is not a literal."""
    start, end = span
    sub = tokens[start : end + 1]
    visible = "".join(token.text for token in sub).strip()
    if len(visible) < 2 or visible[0] != '"' or visible[-1] != '"':
        return None
    selector = visible[1:-1]
    anchor = _string_anchor(sub)
    if not selector or anchor is None:
        return None
    return selector, anchor


def _string_anchor(tokens: list[Token]) -> Anchor | None:
    """
    The ctree item that owns the selector string literal in an argument span.

    Bind to the string's own item — the last `CITEM` anchor governing the visible
    string text — not merely the first anchor. Hex-rays prefixes the span with an
    `ITP` argument-position marker (not a ctree item) and often the enclosing call
    expression's own `CITEM` anchor; anchoring the rewritten selector to either would
    make double-click / `x` resolve to the wrong item (the whole call) or nothing (the
    `ITP` marker) instead of the selector, so both are skipped.

    The string's `cot_str` anchor can sit either just before or just after the opening
    `"`, so scanning stops at the string *body* (the first name-colored run) rather
    than at the quote. A very long selector that hex-rays wraps onto continuation lines
    carries no `cot_str` anchor at all; there the enclosing call's anchor is the best
    (and only) `CITEM` available, so it is used as a fallback.

    Args:
        tokens: The selector argument span's tokens (as sliced by `_selector_of`).

    Returns:
        The string's `CITEM` anchor, the enclosing call's anchor when the wrapped
        string carries none of its own, or `None` if no `CITEM` anchor precedes
        the string body.
    """
    owner: Anchor | None = None
    for token in tokens:
        if token.anchor is not None:
            if token.anchor.kind == AnchorKind.CITEM:
                owner = token.anchor
        elif token.color is not None and token.color != Color.SYMBOL:
            break  # reached the string body
    return owner


def _next_content(tokens: list[Token], i: int) -> int:
    """Index of the next token at/after `i` that is not an anchor mark or blank."""
    while i < len(tokens) and (tokens[i].anchor is not None or tokens[i].is_blank):
        i += 1
    return i


def _real_arg_count(tokens: list[Token], paren: int, *, receiver_in_parens: bool) -> int | None:
    """
    Count the real arguments of the call whose `(` is at/after `paren`.

    Args:
        tokens: The pseudocode tokens.
        paren: Index that should hold the call's opening `(`.
        receiver_in_parens: `True` for `-[…]` instance sends, whose first
            parenthesized item is the receiver and so doesn't count as an argument.

    Returns:
        The real argument count, or `None` if `paren` is not a `(` or the call
        is unterminated.
    """
    if paren >= len(tokens) or not tokens[paren].is_symbol("("):
        return None
    args, _ = split_args(tokens, paren)
    if args is None:
        return None

    def _is_real(span: tuple[int, int]) -> bool:
        # hex-rays leaves position anchors inside otherwise-empty parens, and
        # `split_args` counts those as content — a span with no visible token isn't
        # a real argument.
        return any(not (tokens[k].is_blank or tokens[k].anchor is not None) for k in range(span[0], span[1] + 1))

    visible = sum(1 for span in args if _is_real(span))
    return visible - (1 if receiver_in_parens else 0)


def _zero_arg_colon_strip(tokens: list[Token], i: int) -> str | None:
    """
    New text for the method/selector token at `i` if its trailing colon should go.

    Handles the native `-[Cls sel:]` / `+[Cls sel:]` render (whole call is one
    token; an instance receiver is the first parenthesized item) and the rewritten
    `[recv sel:]` bracket render (the selector is its own token before `]`).

    Returns:
        The colon-stripped token text, or `None` to leave the token unchanged.
    """
    text = tokens[i].text
    if text.endswith(":]") and (text.startswith("-[") or text.startswith("+[")):
        paren = _next_content(tokens, i + 1)
        real = _real_arg_count(tokens, paren, receiver_in_parens=text.startswith("-["))
        return text[:-2] + "]" if real is not None and real <= 0 else None
    if text.endswith(":"):
        close = _next_content(tokens, i + 1)
        if close >= len(tokens) or not tokens[close].is_symbol("]"):
            return None
        paren = _next_content(tokens, close + 1)
        return text[:-1] if _real_arg_count(tokens, paren, receiver_in_parens=False) == 0 else None
    return None


def _strip_zero_arg_colons(tokens: list[Token]) -> bool:
    """
    Drop the trailing selector colon of a message send that takes no arguments.

    A selector whose argument(s) hex-rays could not recover renders with empty (or
    receiver-only) parentheses, e.g. `[v8 setTimeSent:]()` or
    `-[NSMapTable objectForKey:](self->_services)`. With no parameters shown the
    trailing colon just reads as noise, so it is dropped (`init` rather than
    `init:`) — including for multi-colon selectors whose arguments are all missing.
    The token's ctree anchor is preserved, so navigation still resolves to the real
    (colon-bearing) selector.

    Args:
        tokens: The function's pseudocode tokens, mutated in place.

    Returns:
        Whether any selector colon was stripped.
    """
    changed = False
    for i, token in enumerate(tokens):
        if token.color not in (Color.DEMNAME, Color.IMPNAME):
            continue
        new_text = _zero_arg_colon_strip(tokens, i)
        if new_text is not None:
            tokens[i] = replace(token, text=new_text)
            changed = True
    return changed


def write_back(ps: strvec_t, new_lines: list[str]) -> None:
    """
    Replace the pseudocode lines with `new_lines` in place.

    Existing `simpleline_t` objects are reused so their metadata survives. The
    transform never adds lines, so any surplus lines are erased.

    Args:
        ps: The function's pseudocode line vector, modified in place.
        new_lines: The replacement tagged lines, at most as many as `ps` holds.
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


def merge_wrapped_lines(tagged_lines: list[str], code_start: int = 0) -> list[str]:
    """
    Fold wrapped continuation lines back together where the result still fits.

    A line is a *continuation* when the running `()`/`[]` nesting depth at its
    start is greater than zero — i.e. it belongs to an unclosed call/subscript on a
    previous line. Such a line is appended to the line above it (with one separating
    space, or none after an opener / before a closer) as long as the joined visible
    text stays within `MAX_LINE_LENGTH`. Statement boundaries sit at depth 0
    and are never merged, so distinct statements stay on their own lines.

    Only the code section is folded. A wrapped prototype's parameter lines also sit
    at depth > 0, but folding them shrinks the header below the decompiler's recorded
    `cfunc_t.hdrlines`, pushing the first body statements above that boundary —
    where Hex-Rays' item→coordinate lookup no longer finds them, silently dropping
    those items' xrefs.

    Args:
        tagged_lines: The function's tagged pseudocode lines.
        code_start: The index of the first `Section.CODE` line, i.e.
            `cfunc_t.hdrlines` (see `idahelper.pseudocode.Pseudocode.section_of`).
            Lines before it pass through untouched.
    """
    header = tagged_lines[:code_start]
    merged: list[Line] = []
    depth = 0
    for tagged in tagged_lines[code_start:]:
        line = Line.parse(tagged)
        at_continuation = depth > 0
        depth += _bracket_balance(line)
        if merged and at_continuation and _fits(merged[-1], line):
            _append_continuation(merged[-1], line)
        else:
            merged.append(line)
    return header + [line.to_tagged() for line in merged]


def _bracket_balance(line: Line) -> int:
    """The net `()`/`[]` nesting a line opens (`{}` and string contents excluded)."""
    depth = 0
    for token in line.tokens:
        if token.color == Color.SYMBOL:
            depth += token.text.count("(") + token.text.count("[")
            depth -= token.text.count(")") + token.text.count("]")
    return depth


def _fits(target: Line, cont: Line) -> bool:
    """Whether `cont` can be appended to `target` without exceeding the width."""
    body = cont.text.strip()
    if not body:
        return True
    space = 0 if _abuts(target.text, body) else 1
    return len(target.text) + space + len(body) <= MAX_LINE_LENGTH


def _abuts(target_text: str, cont_text: str) -> bool:
    """Whether the continuation should join with no separating space."""
    return target_text[-1:] in "([" or cont_text[:1] in ")];,."


def _append_continuation(target: Line, cont: Line) -> None:
    """
    Append `cont`'s tokens to `target` with exactly one separating space.

    Both edges are normalized — the target's trailing whitespace and the
    continuation's leading indentation are trimmed — so the join never produces a
    double space or a stray space before a closer. A selector stripped from a
    wrapped call can orphan its separating comma on `target` (the comma lived on a
    different line from the selector, so the per-line selector strip could not reach
    it); folding a closer up against that comma would yield an invalid `,)` / `,]`,
    so the dangling comma is dropped first.
    """
    body = _lstrip_indent(cont.tokens)
    text = "".join(token.text for token in body)
    if not text:
        return
    _rstrip_whitespace(target.tokens)
    if text[:1] in ")]" and target.text.rstrip().endswith(","):
        drop_trailing_comma(target.tokens)
        _rstrip_whitespace(target.tokens)
    if not _abuts(target.text, text):
        target.tokens.append(Token(" "))
    target.tokens.extend(body)


def _rstrip_whitespace(tokens: list[Token]) -> None:
    """Trim trailing whitespace from a line's tokens, in place (keeps a trailing anchor)."""
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
    """Drop a continuation line's leading indentation, keeping its anchor marks."""
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
