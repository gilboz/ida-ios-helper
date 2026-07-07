__all__ = ["OrganizeStats", "organize_functions"]

from dataclasses import dataclass

import ida_dirtree
from ida_dirtree import dirtree_t
from idahelper import memory
from idahelper.segments import PredefinedClass, Segment

# Maps a segment name suffix (the part after "module:") to its folder in the functions tree.
FOLDER_BY_SEGMENT_SUFFIX: dict[str, str] = {
    "__stubs": "Stubs/Stubs",
    "__auth_stubs": "Stubs/Auth Stubs",
    "__objc_stubs": "Stubs/Objective-C Stubs",
    "__stub_helper": "Stubs/Stub Helpers",
}
# Suffix of the segments holding a module's real code.
TEXT_SEGMENT_SUFFIX = "__text"
# Folder for functions in executable segments with an unrecognized suffix.
FALLBACK_FOLDER = "Other"


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


def organize_functions() -> OrganizeStats:
    """
    Organize the Functions window folders of a DSC database by module and segment kind.

    Functions in stub segments (`__stubs`, `__auth_stubs`, ...) are moved into
    subfolders of "Stubs", and each module's `__text` functions into a folder
    named after the module. Functions in other executable segments go into
    "Other/<segment suffix>".

    Returns:
        Aggregated move statistics across all executable segments.
    """
    func_dir: dirtree_t = ida_dirtree.get_std_dirtree(ida_dirtree.DIRTREE_FUNCS)
    func_dir.chdir("/")

    stats = OrganizeStats()
    created_folders: set[str] = set()
    for segment in Segment.by_cls(PredefinedClass.CODE):
        folder = _folder_for_segment(segment)
        if folder is None:
            continue
        if folder not in created_folders:
            _make_folder(func_dir, folder)
            created_folders.add(folder)
        stats += _move_segment_functions(func_dir, segment, folder)
    return stats


def _folder_for_segment(segment: Segment) -> str | None:
    """
    Return the destination folder for a segment's functions, or `None` to keep them in root.

    Args:
        segment: An executable segment, named like `module:__suffix` in a DSC database.
    """
    suffix = segment.name.rsplit(":", 1)[-1]
    if suffix == TEXT_SEGMENT_SUFFIX:
        module = segment.base_name
        # A bare `__text` segment has no module prefix; keep its functions in root.
        return module if module != segment.name else None
    return FOLDER_BY_SEGMENT_SUFFIX.get(suffix, f"{FALLBACK_FOLDER}/{suffix}")


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


def _move_segment_functions(func_dir: dirtree_t, segment: Segment, folder: str) -> OrganizeStats:
    """
    Move every function of `segment` into `folder`.

    Items are addressed by name, so a `rename` from the root path to a folder
    path is a move. A function whose name is not found in the root is assumed
    to be already organized and is counted as skipped.

    Args:
        func_dir: The functions dirtree.
        segment: The segment whose functions should be moved.
        folder: Destination folder path.

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

        err = func_dir.rename(name, f"{folder}/{name}")
        if err == ida_dirtree.DTE_OK:
            moved += 1
        elif err == ida_dirtree.DTE_NOT_FOUND:
            skipped += 1
        else:
            failed += 1
    return OrganizeStats(moved=moved, skipped=skipped, failed=failed)
