"""
Clang blocks support: the `clang-blocks-analyzer` pipeline (`analyzer/`) and the
`clang-blocks-optimizer` init-collapsing hook (`optimizer.py`), wired into the plugin
core by `components.py` over the shared struct models in `model/`.
"""

__all__ = [
    "CLANG_BLOCKS_ANALYZER_COMPONENT_NAME",
    "BlocksScan",
    "analyze_blocks_in_func",
    "clang_block_optimizer_component",
    "clang_blocks_analyzer_component",
    "clang_blocks_auto_analyzer_component",
    "rename_blocks_in_func",
    "try_add_block_arg_byref_to_func",
]

from .analyzer.byref_args import try_add_block_arg_byref_to_func
from .analyzer.options import CLANG_BLOCKS_ANALYZER_COMPONENT_NAME
from .analyzer.pipeline import analyze_blocks_in_func
from .analyzer.renamer import rename_blocks_in_func
from .analyzer.scan import BlocksScan
from .components import (
    clang_block_optimizer_component,
    clang_blocks_analyzer_component,
    clang_blocks_auto_analyzer_component,
)
