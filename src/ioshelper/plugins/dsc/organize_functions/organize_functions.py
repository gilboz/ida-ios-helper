__all__ = ["OrganizeStats", "organize_functions"]

from dataclasses import dataclass

import ida_dirtree
from ida_dirtree import dirtree_t
from idahelper import memory
from idahelper.segments import Segment

# Maps a stub-segment name suffix (the part after "module:") to a folder name.
STUB_FOLDER_BY_SUFFIX: dict[str, str] = {
    "__stubs": "Stubs",
    "__auth_stubs": "Auth Stubs",
    "__objc_stubs": "Objective-C Stubs",
    "__stub_helper": "Stub Helpers",
}
# Parent folder for a module's stub segments.
STUBS_FOLDER = "Stubs"
# Suffix of the segments holding a module's real code.
TEXT_SEGMENT_SUFFIX = "__text"
# Folder for functions in executable segments with an unrecognized suffix.
FALLBACK_FOLDER = "Other"
# Segments named like `dyld_shared_cache_arm64e.02:__stubs` belong to the cache itself
# (stub islands and other per-subcache sections), not to a module.
DSC_SEGMENT_PREFIX = "dyld_shared_cache"
DSC_FOLDER = "Cache"


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
    Organize the Functions window folders of a DSC database by module and segment kind.

    Functions in stub segments (`__stubs`, `__auth_stubs`, ...) are moved into
    subfolders of "Stubs", and each module's `__text` functions into a folder
    named after the module. Segments of the cache itself
    (`dyld_shared_cache_arm64e.02:__stubs`, ...) go into "Cache/<subcache>/<kind>".
    Functions in other executable segments go into "Other/<segment suffix>".

    Args:
        only_root: When `True`, only organize functions currently at the tree root
            (a differential pass, e.g. after loading a new dylib module). When
            `False`, move every function to its computed folder wherever it is now.

    Returns:
        Aggregated move statistics across all executable segments.
    """
    func_dir: dirtree_t = ida_dirtree.get_std_dirtree(ida_dirtree.DIRTREE_FUNCS)
    func_dir.chdir("/")

    stats = OrganizeStats()
    created_folders: set[str] = set()
    # Permission-based rather than class-based: the DSC loader does not mark the
    # cache's own segments (stub islands, ...) with the CODE class.
    for segment in (s for s in Segment.get_all() if s.is_executable):
        folder = _folder_for_segment(segment)
        if folder is None:
            continue
        if folder not in created_folders:
            _make_folder(func_dir, folder)
            created_folders.add(folder)
        stats += _move_segment_functions(func_dir, segment, folder, only_root=only_root)

    if not only_root:
        removed = _remove_empty_folders(func_dir)
        if removed:
            print(f"[iOSHelper] removed {removed} empty function folders")
    return stats


def _folder_for_segment(segment: Segment) -> str | None:
    """
    Return the destination folder for a segment's functions, or `None` to keep them in root.

    Args:
        segment: An executable segment, named like `module:__suffix` in a DSC database.
    """
    suffix = segment.name.rsplit(":", 1)[-1]
    module = segment.base_name

    if module.startswith(DSC_SEGMENT_PREFIX):
        # `dyld_shared_cache_arm64e.02:__stubs` -> `Cache/02/Stubs`
        subcache = module.rsplit(".", 1)[-1] if "." in module else module
        kind = STUB_FOLDER_BY_SUFFIX.get(suffix, suffix)
        return f"{DSC_FOLDER}/{subcache}/{kind}"

    if suffix == TEXT_SEGMENT_SUFFIX:
        # A bare `__text` segment has no module prefix; keep its functions in root.
        return module if module != segment.name else None

    if (stub_kind := STUB_FOLDER_BY_SUFFIX.get(suffix)) is not None:
        return f"{STUBS_FOLDER}/{stub_kind}"
    return f"{FALLBACK_FOLDER}/{suffix}"


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


def _move_segment_functions(func_dir: dirtree_t, segment: Segment, folder: str, *, only_root: bool) -> OrganizeStats:
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

    Returns:
        Move statistics for this segment.
    """
    moved = skipped = failed = 0
    for func in segment.functions():
        name = memory.name_from_ea(func.start_ea)
        if not name or "/" in name:
            # A "/" inside the name would be parsed as a path separator.
            failed += 1
            continue

        target = f"{folder}/{name}"
        if only_root:
            source = name
        else:
            source = _current_path(func_dir, func.start_ea)
            if source is None:
                failed += 1
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
    return OrganizeStats(moved=moved, skipped=skipped, failed=failed)


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
