"""
Bracket-syntax sugar for the Obj-C runtime fast-paths hex-rays prints as plain calls.

The clang/ARC optimized entry points (`objc_alloc`, `objc_opt_self`,
`objc_opt_isKindOfClass`, …) decompile to ordinary C-style calls. This module
rewrites them, in place, into the message-send bracket form used by
`objc_msgsend`:

    objc_alloc_init(cls)               -> [[cls alloc] init]
    objc_opt_self(x)                   -> [x self]
    objc_opt_class(x)                  -> [x class]
    objc_opt_new(cls)                  -> [cls new]
    objc_opt_isKindOfClass(obj, cls)   -> [obj isKindOfClass:](cls)
    objc_opt_respondsToSelector(o, s)  -> [o respondsToSelector:](s)

It runs inside the `objc_msgsend` `func_printed` pass (which calls
`rewrite_opt_calls`) and reuses that module's low-level token helpers.
"""

__all__ = ["RUNTIME_BRACKET_CALLS", "rewrite_opt_calls"]

from dataclasses import replace

from idahelper import objc
from idahelper.pseudocode import Anchor, Color, Token

from .selectors import make_selector_token
from .tokens import MAX_REWRITES, find_callee, open_paren_after, split_args

# Each runtime function maps to the chain of message sends it expands to, as
# `(selector, param_count)` pairs. The call's first argument is the receiver; the
# remaining arguments fill the sends' parameters in order. Nullary selectors render
# without parentheses (`[cls alloc]`); a selector that takes a parameter keeps the
# `objc_msgSend` bracket shape (`[obj isKindOfClass:](cls)`).
RUNTIME_BRACKET_CALLS: dict[str, tuple[tuple[str, int], ...]] = {
    "objc_alloc": (("alloc", 0),),
    "objc_alloc_init": (("alloc", 0), ("init", 0)),
    "objc_opt_self": (("self", 0),),
    "objc_opt_class": (("class", 0),),
    "objc_opt_new": (("new", 0),),
    "objc_opt_isKindOfClass": (("isKindOfClass:", 1),),
    "objc_opt_respondsToSelector": (("respondsToSelector:", 1),),
}


def rewrite_opt_calls(tokens: list[Token]) -> dict[int, str] | None:
    """
    Rewrite the runtime calls in `RUNTIME_BRACKET_CALLS` into bracket syntax.

    Args:
        tokens: The function's pseudocode tokens, mutated in place.

    Returns:
        A map of each synthesized selector's ctree-item index to its string, or
        `None` when nothing was rewritten. Sharing this shape with
        `objc_msgsend.rewrite` lets both feed the same selector registry, so the
        runtime fast-path selectors get the same double-click / `x` interactivity as
        `objc_msgSend` ones.
    """
    selectors: dict[int, str] = {}
    pos = 0
    for _ in range(MAX_REWRITES):
        found = find_callee(tokens, pos, RUNTIME_BRACKET_CALLS)
        if found is None:
            break
        pos = found
        sends = RUNTIME_BRACKET_CALLS[tokens[found].text]
        expected_args = 1 + sum(nparams for _, nparams in sends)
        anchor = _preceding_anchor(tokens, found)
        open_paren = open_paren_after(tokens, found)
        # An anchor is required so the synthesized selectors stay navigable; the
        # runtime call always has its ctree anchor preceding it in practice.
        if open_paren is None or anchor is None:
            pos = found + 1
            continue
        args, close = split_args(tokens, open_paren)
        if args is None or len(args) != expected_args:
            pos = found + 1
            continue
        built = _build_opt_bracket(tokens, args, sends, anchor)
        if built is None:
            pos = found + 1
            continue
        bracket, send_selectors = built
        tokens[found : close + 1] = bracket
        selectors.update(send_selectors)
        # Leave `pos` at `found`: tokens[found] is now `[`, and any runtime call kept
        # verbatim in the receiver/arguments lies further on and is picked up next.
    return selectors or None


def _preceding_anchor(tokens: list[Token], i: int) -> Anchor | None:
    """The ctree anchor governing the token at `i` — the nearest preceding anchor mark."""
    j = i - 1
    while j >= 0 and tokens[j].is_blank:
        j -= 1
    return tokens[j].anchor if j >= 0 else None


def _opt_arg(tokens: list[Token], span: tuple[int, int]) -> list[Token]:
    """
    The tokens for one runtime-call argument span.

    Drops leading inlay-hint decoration, and renders a `&OBJC_CLASS___Name` class
    reference as the bare, still-navigable class name `Name`. Anything else (a
    variable, a nested call) is kept verbatim.

    Returns:
        The argument tokens, or an empty list if the span holds no value.
    """
    start, end = span
    i = start
    while i <= end and (tokens[i].is_blank or tokens[i].anchor is not None or tokens[i].color == Color.AUTOCMT):
        i += 1
    if i <= end and tokens[i].is_symbol("&"):
        j = i + 1
        while j <= end and (tokens[j].anchor is not None or tokens[j].is_blank):
            j += 1
        cls = tokens[j] if j <= end else None
        if cls is not None and cls.color in (Color.DEMNAME, Color.IMPNAME):
            cls_name = objc.class_name_from_ref(cls.text)
            if cls_name is not None:
                return [replace(cls, text=cls_name)]
    return tokens[i : end + 1]


def _build_opt_bracket(
    tokens: list[Token],
    args: list[tuple[int, int]],
    sends: tuple[tuple[str, int], ...],
    anchor: Anchor,
) -> tuple[list[Token], dict[int, str]] | None:
    """
    Build the bracket form for a runtime call from its argument spans and send chain.

    `args[0]` is the receiver; the rest fill the sends' parameters in order. Each
    synthesized selector keeps `anchor` (the original call's ctree anchor) so it
    stays navigable via the shared selector registry.

    Returns:
        A `(tokens, selectors)` pair — the bracket tokens plus a map of each
        synthesized selector's ctree-item index to its string — or `None` if the
        receiver span holds no value. A multi-send chain (`alloc` then `init`)
        shares one anchor, so the last send wins that index.
    """
    out = _opt_arg(tokens, args[0])
    if not out:
        return None
    selectors: dict[int, str] = {}
    arg_idx = 1
    for selector, nparams in sends:
        send = [
            Token("[", Color.SYMBOL),
            *out,
            Token(" "),
            make_selector_token(selector, anchor),
            Token("]", Color.SYMBOL),
        ]
        selectors[anchor.index] = selector
        if nparams:
            send.append(Token("(", Color.SYMBOL))
            for k in range(nparams):
                if k:
                    send += [Token(",", Color.SYMBOL), Token(" ")]
                send += _opt_arg(tokens, args[arg_idx])
                arg_idx += 1
            send.append(Token(")", Color.SYMBOL))
        out = send
    return out, selectors
