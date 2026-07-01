"""Low-level token-list utilities shared by the Obj-C bracket-sugar passes.

`objc_msgsend` and `objc_sugar` both post-process the same tokenized
pseudocode, so the call-scanning and argument-splitting primitives they need live
here rather than being reached into across modules.
"""

__all__ = ["MAX_REWRITES", "drop_trailing_comma", "find_callee", "open_paren_after", "split_args"]

from collections.abc import Container

from idahelper.pseudocode import Token

# Guard against pathological input to avoid any chance of an infinite loop.
MAX_REWRITES = 4096


def find_callee(tokens: list[Token], start: int, names: Container[str]) -> int | None:
    """Index of the next colored callee token whose text is in `names`, at/after `start`."""
    for i in range(start, len(tokens)):
        if tokens[i].color is not None and tokens[i].text in names:
            return i
    return None


def open_paren_after(tokens: list[Token], callee: int) -> int | None:
    """Index of the `(` that follows the callee token (skipping anchors/spaces)."""
    i = callee + 1
    while i < len(tokens) and (tokens[i].anchor is not None or tokens[i].is_blank):
        i += 1
    return i if i < len(tokens) and tokens[i].is_symbol("(") else None


def split_args(tokens: list[Token], open_paren: int) -> tuple[list[tuple[int, int]] | None, int]:  # noqa: C901
    """Split a call's arguments into inclusive `(start, end)` token ranges.

    Tracking nesting on `()`/`[]` symbol tokens is enough — string literals are
    single tokens, so parentheses inside them are never miscounted.

    Args:
        tokens: The pseudocode tokens being scanned.
        open_paren: Index of the call's opening `(`.

    Returns:
        `(ranges, close_index)` where each range trims surrounding whitespace but
        keeps anchors, or `(None, -1)` if the matching `)` is missing.
    """
    args: list[tuple[int, int]] = []
    start: int | None = None
    end: int | None = None
    depth = 0

    def flush() -> None:
        nonlocal start, end
        if start is not None:
            args.append((start, end))
        start = end = None

    for i in range(open_paren, len(tokens)):
        token = tokens[i]
        if token.is_symbol("(") or token.is_symbol("["):
            outermost = depth == 0
            depth += 1
            if outermost:
                continue  # the call's own '(' is structure, not argument content
        elif token.is_symbol(")") or token.is_symbol("]"):
            depth -= 1
            if depth == 0:
                flush()
                return args, i
        elif depth == 1 and token.is_symbol(","):
            flush()
            continue
        # Track content of the current argument, trimming surrounding whitespace
        # (anchors count as content so an argument keeps its leading anchor).
        if depth >= 1 and not token.is_blank:
            if start is None:
                start = i
            end = i
    return None, -1


def drop_trailing_comma(tokens: list[Token]) -> None:
    """Remove the last visible comma token from a line's tokens (anchors/blanks kept)."""
    for i in range(len(tokens) - 1, -1, -1):
        token = tokens[i]
        if token.anchor is not None or token.is_blank:
            continue
        if token.is_symbol(","):
            del tokens[i]
        return
