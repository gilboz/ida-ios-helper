"""The blocks analyzer's config schema: the `[clang-blocks-analyzer]` section of `ioshelper.cfg`."""

__all__ = [
    "CLANG_BLOCKS_ANALYZER_COMPONENT_NAME",
    "BlocksAnalyzerOptions",
]

import dataclasses

from ioshelper.base.config import ComponentOptions

CLANG_BLOCKS_ANALYZER_COMPONENT_NAME = "clang-blocks-analyzer"


@dataclasses.dataclass(frozen=True)
class BlocksAnalyzerOptions(ComponentOptions, section=CLANG_BLOCKS_ANALYZER_COMPONENT_NAME):
    """
    The `[clang-blocks-analyzer]` config section: one boolean gate per analysis step,
    plus the `auto` trigger.

    Attributes:
        auto: Whether the pipeline also runs automatically the first time a
            function using blocks is decompiled (off by default). The first
            decompile's text is pre-analysis; a second decompile shows the result.
        byref_args: Whether the `__block` byref argument structs are recovered.
        rename_fields: Whether block capture fields are renamed after the variables
            or struct fields assigned to them.
        retype_fields: Whether block capture fields take the type of the typed
            variables or struct fields assigned to them.
        rename_blocks: Whether default-named block variables get kind-based names
            (`stack_block1`, `global_block1`, `byref_block1`, ...).
    """

    auto: bool = False
    byref_args: bool = True
    rename_fields: bool = True
    retype_fields: bool = True
    rename_blocks: bool = True
