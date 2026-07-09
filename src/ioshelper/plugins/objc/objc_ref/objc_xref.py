"""Cross-reference lookups for Obj-C selectors and stub-backed functions."""

__all__ = ["locate_selector_xrefs", "locate_xrefs", "module_for_ea"]

from dataclasses import dataclass

import ida_kernwin
from ida_kernwin import Choose
from idahelper import file_format, functions, memory, objc, segments
from idahelper.dsc.stubs import DscStubCache
from idahelper.xrefs import get_xrefs_to

# Per-target memory of the last xref the user jumped to, so reopening the chooser
# re-selects it. Lets you walk every call site one Ctrl+4 at a time.
_LAST_XREF_BY_NAME: dict[str, int] = {}


@dataclass
class Xref:
    """
    One resolved cross-reference, as displayed in the chooser.

    Attributes:
        name: Display name of the referencing location (function name, `+offset` suffixed).
        address: Address the reference originates from.
        module: Owning module (or section) of `address`.
    """

    name: str
    address: int
    module: str


def module_for_ea(ea: int) -> str:
    """
    Return the owning module (dyld_shared_cache) or section name for an address.

    Args:
        ea: The address to look up.

    Returns:
        The module/section base name, or `<unknown>` when `ea` is in no segment.
    """
    seg = segments.Segment.by_ea(ea)
    return seg.base_name if seg is not None else "<unknown>"


def _display_name_for_ea(ea: int) -> str:
    """
    Return the name of the function at `ea`, with a `+offset` suffix when `ea` is mid-function.

    Args:
        ea: The address to name.

    Returns:
        The function name (suffixed with `+offset` for a mid-function address), or the
        plain name/hex address when `ea` is not inside a function.
    """
    func_ea = functions.get_start_of_function(ea)
    if func_ea is None:
        return memory.name_from_ea(ea) or f"{ea:#x}"
    name = memory.name_from_ea(func_ea) or f"sub_{func_ea:X}"
    return name if ea == func_ea else f"{name}+{ea - func_ea:08x}"


def locate_xrefs() -> None:
    """
    Locate xrefs for whatever is under the cursor.

    An Obj-C method definition or a selector-dispatch stub (`__objc_stubs`) resolves
    to its selector's `_objc_msgSend$` call sites; anything else resolves to the
    function's xrefs, aggregated across its import/auth stubs.
    """
    current_ea = ida_kernwin.get_screen_ea()
    func_name = functions.get_func_name(current_ea)
    if func_name is None:
        print("No function under cursor")
        return

    # Both an `-[Class sel]` definition and an `_objc_msgSend$sel` stub map to a selector.
    selector = objc.selector_from_method_name(func_name) or objc.selector_from_msgsend_stub(func_name)
    if selector is not None:
        locate_selector_xrefs(selector, module_for_ea(current_ea))
        return

    _locate_function_xrefs(current_ea, func_name)


def locate_selector_xrefs(selector: str, module: str | None = None) -> None:
    """
    Show the call sites of an Obj-C `selector` via its `_objc_msgSend$` stubs.

    Args:
        selector: The selector to look up, e.g. `doFoo:withBar:`. IDA name mangling
            (colons as underscores, `_N` duplicate suffixes) is tolerated.
        module: Module whose xrefs should be listed first in the chooser, typically
            the one the user is currently in.
    """
    print(f"looking for references to selector: {selector} (module: {module})")

    selector_stubs = objc.SelectorToMsgSendCache.get().stubs_for(selector)
    if not selector_stubs:
        print(f"[!] No _objc_msgSend$ stubs found for selector: {selector}")
        return

    print(f"[*] Found {len(selector_stubs)} matching _objc_msgSend$ stub(s):")
    for ea, name in selector_stubs:
        print(f"    {name} at {ea:#x}")

    _popup_xrefs_window(selector, [ea for ea, _ in selector_stubs], module)


def _locate_function_xrefs(ea: int, func_name: str) -> None:
    """
    Show xrefs to the function at `ea`, aggregated across its import/auth stubs.

    On a dyld_shared_cache database the cursor may be on the canonical function or
    on any of its `j_` stubs; both resolve to the same target set through the shared
    stub cache, so one routine's call sites are found across every module. On a
    regular binary the stub cache is skipped entirely and this is plain xrefs to
    the function.

    Args:
        ea: An address inside the function of interest (need not be its start).
        func_name: Name of that function, used for messages and as a naming fallback.
    """
    func_ea = functions.get_start_of_function(ea)
    if func_ea is None:
        print(f"Could not find the start of the function: {func_name}")
        return

    canonical_ea = func_ea
    targets = [func_ea]
    if file_format.is_dsc():
        cache = DscStubCache.get()
        canonical_ea = cache.target_for(func_ea) or func_ea
        targets = [canonical_ea, *cache.stubs_for(canonical_ea)]

    name = memory.name_from_ea(canonical_ea) or func_name
    print(f"looking for references to: {name} (through {len(targets)} function(s))")
    _popup_xrefs_window(name, targets, module_for_ea(ea))


def _popup_xrefs_window(name: str, funcs: list[int], starting_module: str | None = None) -> None:
    """
    Print and pop up a chooser of the code xrefs to any of `funcs`.

    Xrefs originating from within `funcs` themselves (the stubs cross-referencing
    each other) are dropped, and xrefs from `starting_module` are listed first.

    Args:
        name: Display name of the target, used for the chooser title and as the key
            remembering the last visited xref.
        funcs: Addresses whose incoming xrefs are aggregated (the canonical function
            and its stubs).
        starting_module: Module whose xrefs sort to the top of the list.
    """
    func_starts = set(funcs)
    xrefs = [
        Xref(_display_name_for_ea(frm), frm, module_for_ea(frm))
        for func_ea in funcs
        for frm in get_xrefs_to(func_ea)
        if functions.get_start_of_function(frm) not in func_starts
    ]
    # Show xrefs from the same module as the cursor first.
    xrefs.sort(key=lambda x: x.module != starting_module)

    if not xrefs:
        print("[!] Found target(s), but IDA has no code xrefs to them")
        return

    for x in xrefs:
        print(f"0x{x.address:08x} {x.name}")

    last_addr = _LAST_XREF_BY_NAME.get(name)
    default_idx = next((i for i, x in enumerate(xrefs) if x.address == last_addr), None)

    _XrefChooser(f"Xrefs to {name}", name, xrefs, default_idx).show()


class _XrefChooser(Choose):
    """
    Modal chooser listing `Xref` rows; selecting a row jumps to it and remembers it.

    Args:
        title: Window title.
        target_name: Key under which the last visited xref is remembered.
        xrefs: The rows to display.
        default_idx: Row to pre-select, if any.
    """

    def __init__(self, title: str, target_name: str, xrefs: list[Xref], default_idx: int | None = None):
        Choose.__init__(
            self,
            title,
            [
                ["Address", 20 | Choose.CHCOL_EA],
                ["Name", 40 | Choose.CHCOL_FNAME],
                ["Module", 20 | Choose.CHCOL_PLAIN],
            ],
            flags=Choose.CH_RESTORE | Choose.CH_MODAL,
            deflt=default_idx,
        )
        self.target_name = target_name
        self.items = xrefs

    def OnInit(self) -> bool:
        return True

    def OnGetSize(self) -> int:
        return len(self.items)

    def OnGetLine(self, n):
        item = self.items[n]
        return f"{item.address:#x}", item.name, item.module

    def OnGetEA(self, n) -> int:
        return self.items[n].address

    def OnSelectLine(self, n):
        item = self.items[n]
        _LAST_XREF_BY_NAME[self.target_name] = item.address
        ida_kernwin.jumpto(item.address)
        print(hex(item.address))
        return (Choose.NOTHING_CHANGED,)

    def show(self) -> bool:
        """
        Display the chooser modally.

        Returns:
            True if the chooser was shown successfully.
        """
        return self.Show(True) >= 0
