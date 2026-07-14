"""Report the dyld_shared_cache modules to load so the current function's stub calls resolve."""

__all__ = ["report_modules_to_load"]

from collections import defaultdict

import ida_bytes
import ida_funcs
from idahelper import functions, instructions, xrefs
from idahelper.dsc.stubs import is_stub_function, raw_stub_target


def report_modules_to_load(ea: int) -> None:
    """
    Print which unloaded cache modules back the stub calls in the function at `ea`.

    A partial dyld_shared_cache maps only some images, so a call through an import stub can
    land in an image that is not loaded — the decompiler then shows an opaque thunk. For
    every stub the enclosing function calls, this reads the stub's branch target from its
    assembly (`raw_stub_target`), skips the targets already mapped, and groups the rest by
    the cache image that owns them. The owning images are printed so the user can load them
    (via the dscu plugin) and re-decompile with the calls resolved.

    Args:
        ea: Any address inside the function of interest.
    """
    func_ea = functions.get_start_of_function(ea)
    if func_ea is None:
        print("[iOSHelper] no function under cursor")
        return
    func_name = functions.get_func_name(func_ea) or f"sub_{func_ea:X}"

    try:
        from idahelper.dscu import Dsc
    except ImportError:
        print("[iOSHelper] reporting stub modules requires IDA 9.4+ (the dscu service is unavailable)")
        return

    dsc = Dsc.get()
    if dsc is None:
        print("[iOSHelper] current database is not a dyld_shared_cache")
        return

    modules: dict[str, int] = defaultdict(int)
    unresolved = 0
    for stub_ea in _stub_calls_in(func_ea):
        target = raw_stub_target(ida_funcs.get_func(stub_ea))
        if target is None:
            unresolved += 1
            continue
        if ida_bytes.is_mapped(target):
            # Already resolvable in this database — nothing to load for it.
            continue
        info = dsc.locate(target)
        image = dsc.image(info.region.image_index) if info is not None and info.region.image_index >= 0 else None
        if image is None:
            unresolved += 1
            continue
        modules[image.name] += 1

    _print_report(func_name, modules, unresolved)


def _stub_calls_in(func_ea: int) -> set[int]:
    """
    Return the entry addresses of the import stubs the function at `func_ea` calls.

    Args:
        func_ea: Entry address of the function to scan.

    Returns:
        The distinct stub function addresses reached by a call or tail-jump in the function.
    """
    func = ida_funcs.get_func(func_ea)
    stubs: set[int] = set()
    for insn in instructions.from_func(func):
        for target in xrefs.code_xrefs_from(insn.ea):
            callee_ea = functions.get_start_of_function(target)
            if callee_ea is not None and is_stub_function(callee_ea):
                stubs.add(callee_ea)
    return stubs


def _print_report(func_name: str, modules: dict[str, int], unresolved: int) -> None:
    """
    Print the grouped result of `report_modules_to_load` to the console.

    Args:
        func_name: Name of the scanned function.
        modules: Owning image install name -> number of stub calls into it.
        unresolved: Count of stub calls whose target module could not be determined.
    """
    if not modules:
        suffix = f" ({unresolved} could not be resolved from assembly)" if unresolved else ""
        print(f"[iOSHelper] {func_name}: all stub calls already resolve{suffix}")
        return

    stub_count = sum(modules.values())
    print(f"[iOSHelper] {func_name}: {stub_count} stub call(s) reach {len(modules)} unloaded module(s):")
    for name, count in sorted(modules.items(), key=lambda item: (-item[1], item[0])):
        print(f"    {name}  ({count} stub{'s' if count != 1 else ''})")
    if unresolved:
        print(f"    ({unresolved} stub call(s) could not be resolved from assembly)")
    print('    Load them with the dscu plugin ("Load module") and re-decompile to resolve these calls.')
