"""
The block-analysis pipeline, shared by the manual action and the auto analyzer.

A run records a per-function netnode marker that survives IDB reopen; bump
`_ANALYZED_VERSION` after a pipeline change to force re-analysis.
"""

__all__ = [
    "analyze_blocks_in_func",
    "is_func_block_analyzed",
    "mark_func_block_analyzed",
    "sync_block_fields_in_func",
]

import dataclasses

import ida_netnode
from idahelper import objc, widgets

from .byref_args import try_add_block_arg_byref_to_func
from .options import BlocksAnalyzerOptions
from .renamer import rename_blocks_in_func
from .scan import BlocksScan

# Maps a function's entry ea to `_ANALYZED_VERSION`; a different (or absent) value
# means the current pipeline has not run on it.
_ANALYZED_NETNODE = "$ ioshelper.clang-blocks-analyzed"
_ANALYZED_VERSION = 1


def is_func_block_analyzed(func_ea: int) -> bool:
    """
    Whether the block pipeline (this version) has already run on `func_ea`.

    Reads the persisted marker, so it stays true across IDB close/reopen.

    Args:
        func_ea: The function's entry address.

    Returns:
        `True` if a run at the current `_ANALYZED_VERSION` is on record.
    """
    nn = ida_netnode.netnode(_ANALYZED_NETNODE, 0, True)
    return nn.altval(func_ea) == _ANALYZED_VERSION


def mark_func_block_analyzed(func_ea: int) -> None:
    """
    Record that the block pipeline ran on `func_ea`, surviving IDB reopen.

    Args:
        func_ea: The function's entry address.
    """
    nn = ida_netnode.netnode(_ANALYZED_NETNODE, 0, True)
    nn.altset(func_ea, _ANALYZED_VERSION)


def analyze_blocks_in_func(func_ea: int, options: BlocksAnalyzerOptions, *, force: bool = True) -> bool:
    """
    Run the block analysis pipeline on the function at `func_ea`.

    IDA's own stack-block analysis always runs first, followed by one shared scan of
    the fresh decompilation (see `BlocksScan`). The follow-up steps — byref argument
    recovery, capture field renaming/retyping, and block naming — are gated by
    `options` and all reuse that scan; only when the byref recovery changed types is
    the function re-decompiled and re-scanned once, so the renamer sees the new byref
    structs. On completion the function is marked analyzed (see
    `mark_func_block_analyzed`).

    Args:
        func_ea: The function's entry address.
        options: The gates selecting which follow-up steps run.
        force: When true (the manual action), analyze even if the persisted marker says
            this pipeline version already ran on the function. When false (the auto
            analyzer), an already-analyzed function is skipped.

    Returns:
        `True` if at least one follow-up step modified something.
    """
    if not force and is_func_block_analyzed(func_ea):
        return False
    objc.analyze_stack_blocks(func_ea)
    widgets.refresh_pseudocode_widgets()

    changed = False
    # IDA's stack-block analysis just retyped lvars into `Block_layout_*` structs but
    # left the cached decompilation intact, so force a fresh one for the scan to see them.
    scan = BlocksScan.from_ea(func_ea, refresh=True)
    if scan is not None and options.byref_args and try_add_block_arg_byref_to_func(scan):
        changed = True
        # The byref recovery retyped lvars and struct fields; rescan a fresh decompilation.
        scan = BlocksScan.from_ea(func_ea, refresh=True)
    if scan is None:
        print(f"[Error] Failed to decompile func at {func_ea:X}")
    elif options.rename_fields or options.retype_fields or options.rename_blocks:
        changed |= rename_blocks_in_func(scan, options)
    if changed:
        widgets.refresh_pseudocode_widgets()

    mark_func_block_analyzed(func_ea)
    return changed


def sync_block_fields_in_func(func_ea: int, options: BlocksAnalyzerOptions) -> bool:
    """
    Run only the capture-field rename/retype on the function at `func_ea`.

    A lighter pass than `analyze_blocks_in_func` for a function whose blocks are
    already typed — e.g. to re-sync the captures after renaming or retyping the
    variables assigned into them. IDA's stack-block analysis, the byref recovery,
    and the block naming do not run, and the function is not marked analyzed. The
    field steps honor the same `rename-fields` / `retype-fields` gates as the full
    pipeline.

    Args:
        func_ea: The function's entry address.
        options: The gates selecting which of the field steps run.

    Returns:
        `True` if at least one field was modified.
    """
    if not (options.rename_fields or options.retype_fields):
        return False
    scan = BlocksScan.from_ea(func_ea)
    if scan is None:
        print(f"[Error] Failed to decompile func at {func_ea:X}")
        return False
    changed = rename_blocks_in_func(scan, dataclasses.replace(options, rename_blocks=False))
    if changed:
        widgets.refresh_pseudocode_widgets()
    return changed
