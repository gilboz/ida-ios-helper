"""
Dump pseudocode with visible IDA color and anchor tags.

A thin renderer over `idahelper.pseudocode`: each tagged line is parsed
into tokens and the invisible color / anchor escapes are spelled out as
bracketed markers (`[ON KEYWORD]`, `[OFF KEYWORD]`, `[ADDR CITEM#3 0x…]`,
`[INV]`), while the visible text is left untouched. Lines are grouped by
section (declaration / variables / code) so the body is easy to find.
"""

import ida_hexrays
import idc
from idahelper.pseudocode import Anchor, Line, Pseudocode, Section


def _anchor_label(anchor: Anchor) -> str:
    """Format a decoded anchor like `CITEM#3 0x000…003` (or a plain `0x…`)."""
    if anchor.kind is None:
        return f"0x{anchor.raw.upper()}"
    return f"{anchor.kind.name}#{anchor.index} 0x{anchor.raw.upper()}"


def annotate_line(line: Line, *, show_addr_tags: bool = True) -> str:
    """
    Render one parsed line with its color and anchor escapes spelled out.

    Args:
        line: A line parsed by `idahelper.pseudocode.Line.parse`.
        show_addr_tags: When `False`, `[ADDR …]` markers are omitted.

    Returns:
        The line text with annotations inlined.
    """
    parts: list[str] = []
    for token in line.tokens:
        if token.anchor is not None:
            if show_addr_tags:
                parts.append(f"[ADDR {_anchor_label(token.anchor)}]")
        elif token.inverse:
            parts.append("[INV]")
        elif token.color is not None:
            parts.append(f"[ON {token.color.name}]{token.text}[OFF {token.color.name}]")
        else:
            parts.append(token.text)
    return "".join(parts)


def annotate_tagged_line(tagged: str, *, show_addr_tags: bool = True) -> str:
    """Parse a raw tagged line and annotate it (convenience wrapper)."""
    return annotate_line(Line.parse(tagged), show_addr_tags=show_addr_tags)


def dump_ps(*, ea: int | None = None, out_path: str = "/tmp/pseudocode.txt", show_addr_tags: bool = True) -> str:  # noqa: S108
    """
    Decompile a function and write annotated, section-grouped pseudocode to disk.

    Args:
        ea: Function entry point. Defaults to `idc.get_screen_ea()`.
        out_path: Output file path for the annotated pseudocode.
        show_addr_tags: Passed through to `annotate_line`.

    Returns:
        The annotated pseudocode string that was written to `out_path`.

    Raises:
        RuntimeError: If decompilation fails for `ea`.
    """
    ea = ea if ea is not None else idc.get_screen_ea()
    cfunc = ida_hexrays.decompile(ea)
    if cfunc is None:
        raise RuntimeError(f"decompile({ea:#x}) failed")

    pc = Pseudocode.from_cfunc(cfunc)
    parts: list[str] = []
    section: Section | None = None
    for lnnum, line in enumerate(pc.lines):
        line_section = pc.section_of(lnnum)
        if line_section is not section:
            section = line_section
            parts.append(f"// ===== {section.name} =====")
        parts.append(annotate_line(line, show_addr_tags=show_addr_tags))
    annotated = "\n".join(parts)

    with open(out_path, "w", encoding="utf-8") as f:
        f.write(annotated)

    print(f"written {len(annotated)} characters to {out_path}")
    return annotated
