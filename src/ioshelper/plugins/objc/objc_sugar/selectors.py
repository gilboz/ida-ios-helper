"""
Shared selector-token plumbing for the Obj-C bracket-sugar passes.

Both `objc_msgsend` (`objc_msgSend` calls) and `objc_opt` (the runtime
fast-paths) synthesize selector name tokens. This module is the single owner of what a
selector token looks like and of the per-function registry that makes those tokens
interactive: double-clicking one launches IDA's selector-jump action, and pressing
`x` over it lists the selector's call sites (see `locate_selector_xrefs`).
Routing every pass through here keeps the interactivity working uniformly — that is why
`objc_opt` selectors behave the same as `objc_msgSend` ones.
"""

__all__ = [
    "handle_selector_double_click",
    "handle_selector_xref",
    "make_selector_token",
    "register_selectors",
    "selector_under_cursor",
]

import ida_hexrays
import ida_kernwin
from ida_hexrays import vdui_t
from idahelper.pseudocode import Anchor, Color, Token

from ..objc_ref.objc_xref import locate_selector_xrefs, module_for_ea

# IDA's built-in "Jump by selector..." action, launched on a double-clicked selector.
JUMP_SELECTOR_ACTION = "objc:JumpSelector"

# The 'x' key (IDA's "list cross-references"). When pressed over a rewritten
# selector we show that selector's call sites instead of IDA's default xrefs to
# the underlying selector-string literal.
XREF_KEY = ord("X")

# Per-function map: selector ctree-item index -> selector string. Populated when a
# function is printed, read back when its selector is double-clicked / xref'd.
_selectors_by_func: dict[int, dict[int, str]] = {}


def make_selector_token(text: str, anchor: Anchor) -> Token:
    """
    Build a selector name token anchored to its ctree item.

    The anchor decides what hovering / double-clicking / `x` resolve to, so callers
    pass the selector's own ctree item (`objc_msgSend`) or the originating runtime
    call's item (`objc_opt`).
    """
    return Token(text, Color.DEMNAME, anchor=anchor)


def register_selectors(entry_ea: int, selectors: dict[int, str]) -> None:
    """Record a function's rewritten selectors (ctree-item index -> string) for lookup."""
    _selectors_by_func[entry_ea] = selectors


def selector_under_cursor(vu: vdui_t, flags: int) -> str | None:
    """
    Return the selector string for the rewritten selector token under the cursor.

    Args:
        vu: The decompiler view to inspect.
        flags: Cursor source — `USE_MOUSE` for clicks, `USE_KEYBOARD` for keys.

    Returns:
        The selector string, or `None` if the cursor is not on a rewritten selector.
    """
    selectors = _selectors_by_func.get(vu.cfunc.entry_ea)
    if not selectors or not vu.get_current_item(flags):
        return None
    item = vu.item
    if not item.is_citem():
        return None
    return selectors.get(item.it.index)


def handle_selector_double_click(vu: vdui_t) -> int:
    """
    Forward a double-click on a rewritten selector to IDA's selector-jump action.

    Returns:
        `1` if the cursor was on a rewritten selector (handled), else `0`.
    """
    if selector_under_cursor(vu, ida_hexrays.USE_MOUSE) is None:
        return 0
    ida_kernwin.process_ui_action(JUMP_SELECTOR_ACTION)
    return 1


def handle_selector_xref(vu: vdui_t, key_code: int, shift_state: int) -> int:
    """
    List a rewritten selector's call sites when `x` is pressed over it.

    Returns:
        `1` if `x` was handled on a rewritten selector, else `0`.
    """
    if key_code != XREF_KEY or shift_state != 0:
        return 0
    selector = selector_under_cursor(vu, ida_hexrays.USE_KEYBOARD)
    if selector is None:
        return 0
    locate_selector_xrefs(selector, module_for_ea(vu.cfunc.entry_ea))
    return 1
