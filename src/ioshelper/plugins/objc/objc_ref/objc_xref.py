__all__ = ["locate_selector_xrefs", "locate_xrefs", "module_for_ea", "refresh_selector_stub_cache"]

import re
from dataclasses import dataclass
from itertools import count

import ida_kernwin
import idaapi
import idautils
import idc
from ida_kernwin import Choose
from idahelper import segments

# Taken from: https://github.com/doronz88/ida-scripts/blob/main/objc_hotkeys.py
OBJC_MSGSEND_PREFIX = "_objc_msgSend$"

# Lazily built index: normalized selector -> [(stub_ea, stub_name), ...].
# Built once on first lookup; call refresh_selector_stub_cache() after re-running
# the stub renamer to rebuild it.
_STUB_CACHE: dict[str, list[tuple[int, str]]] | None = None

# Per-target memory of the last xref the user jumped to, so reopening the chooser
# re-selects it. Lets you walk every call site one Ctrl+4 at a time.
_LAST_XREF_BY_NAME: dict[str, int] = {}


@dataclass
class Xref:
    name: str
    address: int
    module: str


def module_for_ea(ea: int) -> str:
    """Return the owning module (dyld_shared_cache) or section name for an address."""
    seg = segments.get_segment_by_ea(ea)
    return seg.base_name if seg is not None else "<unknown>"


def get_name_for_ea(ea: int) -> str:
    func_name = idc.get_func_name(ea)
    func_address = idc.get_name_ea_simple(func_name)
    return func_name if ea == func_address else f"{func_name}+{ea - func_address:08x}"


# ---------------------------------------------------------------------------
# Selector -> stub matching.
#
# Resilient to the iOS 27 stub-naming changes: instead of doing exact-name
# lookups (which broke), index every _objc_msgSend$ function once and match
# selectors after normalization (colons -> underscores, stripping IDA's "_N" /
# "__0" duplicate suffixes).
# ---------------------------------------------------------------------------


def strip_ida_duplicate_suffix(s: str) -> str:
    """Strip IDA's duplicate-name suffix: foo_0 / foo_1 / foo_123 -> foo."""
    return re.sub(r"_\d+$", "", s)


def normalize_selector(s: str) -> str:
    """Canonical key used for matching: foo:bar: -> foo_bar_ ; foo_bar__0 -> foo_bar_."""
    if not s:
        return ""

    s = strip_ida_duplicate_suffix(s)
    return s.replace(":", "_")


def build_stub_cache() -> dict[str, list[tuple[int, str]]]:
    """
    Index every _objc_msgSend$ function under several keys so a selector can be
    matched regardless of how IDA mangled the stub name.

    Returns: normalized_selector -> [(stub_ea, stub_name), ...].
    """
    cache: dict[str, list[tuple[int, str]]] = {}

    for func_ea in idautils.Functions():
        name = idc.get_func_name(func_ea) or idc.get_name(func_ea, idaapi.GN_VISIBLE)
        if not name or not name.startswith(OBJC_MSGSEND_PREFIX):
            continue

        stub_selector = name[len(OBJC_MSGSEND_PREFIX) :]
        keys = {
            stub_selector,
            strip_ida_duplicate_suffix(stub_selector),
            normalize_selector(stub_selector),
        }
        for key in keys:
            cache.setdefault(key, []).append((func_ea, name))

    return cache


def refresh_selector_stub_cache() -> None:
    """Rebuild the stub index. Call this after re-running the stub renamer."""
    global _STUB_CACHE

    _STUB_CACHE = build_stub_cache()
    count_entries = sum(len(v) for v in _STUB_CACHE.values())
    print(f"[*] Refreshed objc_msgSend stub cache: {count_entries} indexed entries")


def find_stubs_for_selector(selector: str) -> list[tuple[int, str]]:
    """Return sorted [(stub_ea, stub_name), ...] matching `selector`."""
    global _STUB_CACHE

    if _STUB_CACHE is None:
        print("[*] Building objc_msgSend stub cache...")
        refresh_selector_stub_cache()
        assert _STUB_CACHE is not None

    wanted_keys = {
        selector,
        selector.replace(":", "_"),
        normalize_selector(selector),
    }

    found: dict[int, str] = {}
    for key in wanted_keys:
        for ea, name in _STUB_CACHE.get(key, []):
            found[ea] = name

    return sorted(found.items())


# ---------------------------------------------------------------------------
# Entry point + xref collection.
# ---------------------------------------------------------------------------


def locate_xrefs() -> None:
    """
    Locate xrefs for whatever is under the cursor: an Obj-C method's selector
    (via its _objc_msgSend$ stubs) or an ordinary function / stub.
    """
    current_ea = idc.get_screen_ea()
    func_name = idc.get_func_name(current_ea)
    if not func_name:
        print("No function under cursor")
        return

    # Obj-C method, e.g. -[MSPSharedTripRelay _handleChunk:fromID:...].
    if "[" in func_name:
        try:
            selector = func_name.split(" ")[1].split("]")[0]
        except IndexError:
            print("Failed to find current selector")
            return
        locate_selector_xrefs(selector, module_for_ea(current_ea))
        return

    # Ordinary function / stub, e.g. _some_function.
    if func_name.startswith("_"):
        root = re.sub(r"^_|_\d+$", "", func_name)  # strip leading _ and trailing _%d
        locate_stub_xrefs(root)
        return

    print(f"Don't know how to locate xrefs for: {func_name}")


def locate_selector_xrefs(selector: str, module: str | None = None) -> None:
    print(f"looking for references to selector: {selector} (module: {module})")

    stubs = find_stubs_for_selector(selector)
    if not stubs:
        print(f"[!] No {OBJC_MSGSEND_PREFIX} stubs found for selector: {selector}")
        print("[*] Tried:")
        print(f"    {OBJC_MSGSEND_PREFIX}{selector}")
        print(f"    {OBJC_MSGSEND_PREFIX}{selector.replace(':', '_')}")
        print(f"    normalized key: {normalize_selector(selector)}")
        return

    print(f"[*] Found {len(stubs)} matching {OBJC_MSGSEND_PREFIX} stub(s):")
    for ea, name in stubs:
        print(f"    {name} at {ea:#x}")

    popup_xrefs_window(selector, [ea for ea, _ in stubs], module)


def locate_stub_xrefs(root: str) -> None:
    print(f"looking for references to stub: {root}")

    funcs: list[int] = []

    def check_funcname(name: str) -> bool:
        ea = idc.get_name_ea_simple(name)
        if ea != idaapi.BADADDR:
            funcs.append(ea)
            return True
        return False

    check_funcname(f"_{root}")
    check_funcname(f"j__{root}")

    for i in count():
        if not check_funcname(f"_{root}_{i}"):
            break

    for i in count():
        if not check_funcname(f"j__{root}_{i}"):
            break

    if not funcs:
        print("Could not find stub call sites")
        return

    popup_xrefs_window(root, funcs)


def popup_xrefs_window(name: str, funcs: list[int], starting_module: str | None = None) -> None:
    funcs_names = {idc.get_func_name(ea) for ea in funcs}
    xrefs = [
        Xref(get_name_for_ea(xref.frm), xref.frm, module_for_ea(xref.frm))
        for func_ea in funcs
        for xref in idautils.XrefsTo(func_ea)
        if idc.get_func_name(xref.frm) not in funcs_names
    ]
    # Show xrefs from the same module as the cursor first.
    xrefs.sort(key=lambda x: x.module != starting_module)

    if not xrefs:
        print("[!] Found stub(s), but IDA has no code xrefs to them")
        return

    for x in xrefs:
        print(f"0x{x.address:08x} {x.name}")

    last_addr = _LAST_XREF_BY_NAME.get(name)
    default_idx = next((i for i, x in enumerate(xrefs) if x.address == last_addr), None)

    XrefChooser(f"Xrefs to {name}", name, xrefs, default_idx).show()


class XrefChooser(Choose):
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
        return self.Show(True) >= 0
