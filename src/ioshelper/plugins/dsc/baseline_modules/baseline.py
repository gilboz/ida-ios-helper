"""Offer to load the high-value dyld_shared_cache modules ioshelper's sugar depends on."""

from __future__ import annotations

__all__ = ["offer_to_load_missing_baseline"]

from typing import TYPE_CHECKING

import ida_auto
import ida_hexrays
import ida_kernwin
from idahelper import runtime

if TYPE_CHECKING:
    from idahelper.dscu import Dsc

# Install names of the modules whose absence most degrades ioshelper's output on a partial
# cache: without them, calls into the Obj-C runtime, os_log, and the base frameworks stay as
# opaque `j_...` stub thunks, so neither IDA's thunk resolution nor the os_log / Obj-C sugar
# can fire. Keyed by install name, which is what the dscu service resolves.
IMPORTANT_BASELINE_MODULES: tuple[str, ...] = (
    "/usr/lib/libobjc.A.dylib",
    "/usr/lib/system/libsystem_trace.dylib",
    "/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation",
    "/System/Library/Frameworks/Foundation.framework/Foundation",
)


def offer_to_load_missing_baseline() -> None:
    """
    Prompt once, on open, to load the important baseline modules a partial cache is missing.

    Does nothing when there is no UI to prompt through, when the database is not a
    dyld_shared_cache, when the dscu service is unavailable (pre-9.4), or when every baseline
    module is already loaded.
    """
    if runtime.is_headless():
        return

    try:
        from idahelper.dscu import Dsc
    except ImportError:
        return

    dsc = Dsc.get()
    if dsc is None:
        return

    missing = _missing_baseline(dsc)
    if not missing:
        return

    listing = "\n".join(f"  - {name}" for name, _ in missing)
    prompt = (
        f"{len(missing)} baseline module(s) that improve decompilation are not loaded:\n\n"
        f"{listing}\n\n"
        "Load them now? This maps them into the database and re-runs auto-analysis."
    )
    if ida_kernwin.ask_yn(ida_kernwin.ASKBTN_YES, prompt) != ida_kernwin.ASKBTN_YES:
        return

    _load_and_refresh(dsc, missing)


def _missing_baseline(dsc: Dsc) -> list[tuple[str, int]]:
    """
    Return each baseline module present in the cache but not yet loaded.

    Args:
        dsc: The shared-cache facade for the current database.

    Returns:
        The `(install name, image index)` of every `IMPORTANT_BASELINE_MODULES` entry that
        exists in this cache but is not loaded, in declaration order.
    """
    missing: list[tuple[str, int]] = []
    for name in IMPORTANT_BASELINE_MODULES:
        index = dsc.image_index(name)
        if index is not None and not dsc.is_image_loaded(index):
            missing.append((name, index))
    return missing


def _load_and_refresh(dsc: Dsc, modules: list[tuple[str, int]]) -> None:
    """
    Load the given modules, wait for analysis, and refresh the stub cache, decompiler, and views.

    Args:
        dsc: The shared-cache facade for the current database.
        modules: The `(install name, image index)` pairs to load.
    """
    from idahelper.dsc.stubs import DscStubCache

    loaded = [name for name, index in modules if dsc.load_image(index)]
    if not loaded:
        print("[iOSHelper] no baseline modules could be loaded")
        return

    ida_auto.auto_wait()
    # The stub landscape changed; rebuild the shared cache and drop stale pseudocode.
    DscStubCache.refresh()
    ida_hexrays.clear_cached_cfuncs()
    ida_kernwin.refresh_idaview_anyway()
    print(f"[iOSHelper] loaded {len(loaded)} baseline module(s); re-decompile to see resolved calls")
