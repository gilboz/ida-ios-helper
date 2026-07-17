"""Organize the Functions window of a DSC database: loaded modules' code by module, dyld stubs out of the way."""

__all__ = ["OrganizeStats", "organize_functions"]

from collections import Counter
from dataclasses import dataclass
from typing import TYPE_CHECKING

import ida_dirtree
from ida_dirtree import dirtree_t
from idahelper import memory
from idahelper.dsc.stubs import StubSegmentKind, is_cache_segment, stub_segment_kind
from idahelper.segments import Segment

if TYPE_CHECKING:
    from idahelper.dscu import Dsc

# Top-level folder for every flavor of dyld stub trampoline — they are noise in the
# Functions window, so they all get tucked into one place, subdivided by kind.
DYLD_STUBS_FOLDER = "Dyld Stubs"
# Subfolder of `Dyld Stubs` per stub segment flavor.
STUB_FOLDER_BY_KIND: dict[StubSegmentKind, str] = {
    StubSegmentKind.STUBS: "Stubs",
    StubSegmentKind.AUTH_STUBS: "Auth Stubs",
    StubSegmentKind.OBJC_STUBS: "Objective-C Stubs",
    StubSegmentKind.STUB_HELPER: "Stub Helpers",
    StubSegmentKind.DELAY_STUBS: "Delay Stubs",
    StubSegmentKind.DELAY_HELPER: "Delay Helpers",
    StubSegmentKind.LAZY_HELPERS: "Lazy Helpers",
    StubSegmentKind.CACHE_STUB_ISLAND: "Stub Islands",
    # The dyld-synthesized `_objc_msgSend$sel` extras are the same trampolines as a
    # module's `__objc_stubs`, so they share a folder.
    StubSegmentKind.CACHE_OBJC_MSGSEND: "Objective-C Stubs",
}
# Catch-all for functions that belong to no loaded module and are not stubs: GOT pointer
# slots IDA turned into functions, cache `__TEXT` mapping slices, and code of modules that
# are not loaded. They land here rather than at the tree root or in a module-named folder
# (which would wrongly imply the module is loaded).
OTHER_FOLDER = "Other"


@dataclass(frozen=True, slots=True)
class OrganizeStats:
    """
    Result of an organize run.

    Attributes:
        moved: Functions moved into a folder.
        skipped: Functions left in place (typically already organized).
        failed: Functions that could not be moved.
    """

    moved: int = 0
    skipped: int = 0
    failed: int = 0

    def __add__(self, other: "OrganizeStats") -> "OrganizeStats":
        return OrganizeStats(
            moved=self.moved + other.moved,
            skipped=self.skipped + other.skipped,
            failed=self.failed + other.failed,
        )


def organize_functions(*, only_root: bool = True) -> OrganizeStats:
    """
    Organize the Functions window folders of a DSC database.

    Every dyld stub trampoline — a module's `__stubs`/`__auth_stubs`/`__objc_stubs`/... and
    the cache's own stub islands and objc_msgSend extras regions — goes into a subfolder of
    "Dyld Stubs"; those segments are recognized by kind, not by permissions, since the DSC
    loader leaves some of them non-executable. Each *loaded* module's remaining functions go
    into a folder named after the module. Everything else with functions — GOT pointer slots,
    cache mapping slices, and code of modules that are not loaded — goes into "Other", so a
    full pass leaves no functions at the tree root and never names a folder after an unloaded
    module.

    Args:
        only_root: When `True`, only organize functions currently at the tree root
            (a differential pass, e.g. after loading a new dylib module). When
            `False`, move every function to its computed folder wherever it is now.

    Returns:
        Aggregated move statistics across all organized segments.
    """
    func_dir: dirtree_t = ida_dirtree.get_std_dirtree(ida_dirtree.DIRTREE_FUNCS)
    func_dir.chdir("/")
    dsc = _get_dsc()
    print(f"[iOSHelper] organizing functions into folders ({'new functions only' if only_root else 'full pass'})")
    if dsc is None:
        print("[iOSHelper] dscu service unavailable (IDA < 9.4): treating every module section as loaded")

    stats = OrganizeStats()
    created_folders: set[str] = set()
    moved_per_folder: Counter[str] = Counter()
    failure_examples: list[str] = []
    for segment in Segment.get_all():
        if next(segment.functions(), None) is None:
            continue
        folder = _folder_for_segment(segment, dsc)
        if folder not in created_folders:
            _make_folder(func_dir, folder)
            created_folders.add(folder)
        segment_stats = _move_segment_functions(
            func_dir, segment, folder, only_root=only_root, failures=failure_examples
        )
        moved_per_folder[folder.split("/", 1)[0]] += segment_stats.moved
        stats += segment_stats

    _print_summary(stats, moved_per_folder, failure_examples)
    if not only_root:
        removed = _remove_empty_folders(func_dir)
        if removed:
            print(f"[iOSHelper] removed {removed} empty function folder(s)")
        _warn_if_root_not_empty(func_dir)
    return stats


def _get_dsc() -> "Dsc | None":
    """Return the dscu facade for the current database, or `None` on IDA < 9.4."""
    try:
        from idahelper.dscu import Dsc
    except ImportError:
        return None
    return Dsc.get()


def _folder_for_segment(segment: Segment, dsc: "Dsc | None") -> str:
    """
    Return the destination folder for a segment's functions.

    Every function-bearing segment maps to some folder, so a full pass leaves the tree root
    empty: stubs to "Dyld Stubs", a loaded module's sections to its module folder, and
    anything else to "Other".

    Args:
        segment: A segment holding at least one function.
        dsc: The dscu facade, used to tell a loaded module's sections from unloaded code;
            `None` (IDA < 9.4) treats every module section as loaded.
    """
    if (kind := stub_segment_kind(segment)) is not None:
        return f"{DYLD_STUBS_FOLDER}/{STUB_FOLDER_BY_KIND[kind]}"
    if _is_loaded_module_section(segment, dsc):
        return segment.base_name
    return OTHER_FOLDER


def _is_loaded_module_section(segment: Segment, dsc: "Dsc | None") -> bool:
    """
    Whether the segment is a section (`module:__section`) of a module loaded into the database.

    Args:
        segment: A segment holding at least one function.
        dsc: The dscu facade for the current database, or `None` on IDA < 9.4.
    """
    if is_cache_segment(segment) or segment.base_name == segment.name:
        # A cache-owned segment or a bare (colon-less) section is not a module section.
        return False
    if dsc is None:
        # IDA < 9.4 cannot report load state; assume module sections belong to loaded modules.
        return True
    region = dsc.region_at(segment.start_ea)
    return region is not None and region.image_index >= 0 and dsc.is_image_loaded(region.image_index)


def _make_folder(func_dir: dirtree_t, path: str) -> None:
    """
    Create `path` in the tree, including intermediate folders.

    Args:
        func_dir: The functions dirtree.
        path: A "/"-separated folder path relative to the root.
    """
    current = ""
    for part in path.split("/"):
        current = f"{current}/{part}" if current else part
        err = func_dir.mkdir(current)
        if err not in (ida_dirtree.DTE_OK, ida_dirtree.DTE_ALREADY_EXISTS):
            print(f"[iOSHelper] failed to create functions folder {current!r}: {dirtree_t.errstr(err)}")


def _move_segment_functions(
    func_dir: dirtree_t, segment: Segment, folder: str, *, only_root: bool, failures: list[str]
) -> OrganizeStats:
    """
    Move every function of `segment` into `folder`.

    Items are addressed by path, so a `rename` to a folder path is a move.

    Args:
        func_dir: The functions dirtree.
        segment: The segment whose functions should be moved.
        folder: Destination folder path.
        only_root: When `True`, source paths are the tree root: a function not
            found there is assumed to be already organized and counted as skipped.
            When `False`, each function is moved from wherever it currently is.
        failures: Names of functions that could not be moved are appended here,
            up to a few examples, for the run summary.

    Returns:
        Move statistics for this segment.
    """
    moved = skipped = failed = 0
    for func in segment.functions():
        name = memory.name_from_ea(func.start_ea)
        if not name or "/" in name:
            # A "/" inside the name would be parsed as a path separator.
            failed += 1
            _record_failure(failures, name or f"<unnamed {func.start_ea:#x}>")
            continue

        target = f"{folder}/{name}"
        if only_root:
            source = name
        else:
            source = _current_path(func_dir, func.start_ea)
            if source is None:
                failed += 1
                _record_failure(failures, name)
                continue
            if source == target:
                skipped += 1
                continue

        err = func_dir.rename(source, target)
        if err == ida_dirtree.DTE_OK:
            moved += 1
        elif err == ida_dirtree.DTE_NOT_FOUND:
            skipped += 1
        else:
            failed += 1
            _record_failure(failures, name)
    return OrganizeStats(moved=moved, skipped=skipped, failed=failed)


def _record_failure(failures: list[str], name: str, limit: int = 3) -> None:
    """Keep up to `limit` example names of functions that could not be moved."""
    if len(failures) < limit:
        failures.append(name)


def _print_summary(stats: OrganizeStats, moved_per_folder: Counter[str], failure_examples: list[str]) -> None:
    """
    Print the outcome of an organize run to the console.

    Args:
        stats: Aggregated move statistics.
        moved_per_folder: Moved-function count per top-level destination folder.
        failure_examples: Example names of functions that could not be moved.
    """
    special = {DYLD_STUBS_FOLDER, OTHER_FOLDER}
    module_moved = sum(count for folder, count in moved_per_folder.items() if folder not in special)
    module_count = sum(1 for folder in moved_per_folder if folder not in special)
    breakdown = (
        f" ({moved_per_folder[DYLD_STUBS_FOLDER]} to {DYLD_STUBS_FOLDER!r},"
        f" {module_moved} to {module_count} module folder(s),"
        f" {moved_per_folder[OTHER_FOLDER]} to {OTHER_FOLDER!r})"
        if stats.moved
        else ""
    )
    print(
        f"[iOSHelper] organized functions: {stats.moved} moved{breakdown}, {stats.skipped} skipped, {stats.failed} failed"
    )
    if failure_examples:
        print(f"[iOSHelper] could not move e.g.: {', '.join(failure_examples)}")


def _warn_if_root_not_empty(func_dir: dirtree_t) -> None:
    """
    Warn if any function is still at the tree root after a full pass.

    A full pass files every function-bearing segment, so a non-empty root points at a
    function the segment scan did not reach (e.g. a name clash that failed to move).

    Args:
        func_dir: The functions dirtree, positioned at the root.
    """
    remaining = _count_root_functions(func_dir)
    if remaining:
        print(f"[iOSHelper] warning: {remaining} function(s) still at the Functions window root")


def _count_root_functions(func_dir: dirtree_t) -> int:
    """Count the function entries (not folders) directly under the tree root."""
    count = 0
    it = ida_dirtree.dirtree_iterator_t()
    ok = func_dir.findfirst(it, "*")
    while ok:
        if not func_dir.resolve_cursor(it.cursor).isdir:
            count += 1
        ok = func_dir.findnext(it)
    return count


class _FolderCollector(ida_dirtree.dirtree_visitor_t):
    """Collect the path and directory index of every folder in the tree."""

    def __init__(self, func_dir: dirtree_t):
        super().__init__()
        self._func_dir = func_dir
        self.folders: list[tuple[str, int]] = []

    def visit(self, cursor, de) -> int:
        if de.isdir:
            path = self._func_dir.get_abspath(cursor)
            if path and path != "/":
                self.folders.append((path, de.idx))
        return 0


def _remove_empty_folders(func_dir: dirtree_t) -> int:
    """
    Remove folders that contain no entries, deepest-first so that folders holding
    only empty subfolders are removed too.

    Returns:
        The number of folders removed.
    """
    # Modifying the tree during traversal is undefined behavior: collect first, delete after.
    collector = _FolderCollector(func_dir)
    func_dir.traverse(collector)

    removed = 0
    for path, diridx in sorted(collector.folders, key=lambda item: item[0].count("/"), reverse=True):
        if func_dir.get_dir_size(diridx) == 0 and func_dir.rmdir(path) == ida_dirtree.DTE_OK:
            removed += 1
    return removed


def _current_path(func_dir: dirtree_t, func_ea: int) -> str | None:
    """
    Return the function's current path in the tree (without the leading "/"), or `None`.

    In the standard functions dirtree, an entry's inode is the function's start EA
    (`DSF_INODE_EA`).
    """
    cursor = func_dir.find_entry(ida_dirtree.direntry_t(func_ea, False))
    if not cursor.valid():
        return None
    path = func_dir.get_abspath(cursor)
    if not path:
        return None
    return path.removeprefix("/")
