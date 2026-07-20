"""
Name source: the function's own Obj-C selector names its arguments.

For a method named `-[Class doFoo:withBar:]` / `+[Class ...]` the decompiler's default
`a1`, `a2` ... arguments map to the Obj-C calling layout:

    a1 -> self          (the receiver, left untouched)
    a2 -> sel           (the selector / _cmd)
    a3 -> a name guessed from the selector (`initWithFrame:` -> `frame`,
          `tableView:didSelectRowAtIndexPath:` -> `table_view`), falling back to `implicit_arg`
    a4+ -> selector keyword pieces

All derived names are converted to snake_case. Only arguments that still carry their
default `aN` name are candidates, so manual renames and names from a user-applied
prototype are preserved.
"""

__all__ = ["collect_arg_candidates"]

from ida_hexrays import cfunc_t, lvar_t
from idahelper import memory, naming, objc

from .heuristics import guess_implicit_arg_name


def collect_arg_candidates(decompiled: cfunc_t) -> dict[str, str]:
    """
    Map each still-default argument's lvar name to the name derived from the selector.

    Args:
        decompiled: The function's in-flight decompilation.

    Returns:
        `{current lvar name: proposed base name}`, empty when the function is not an
        Obj-C method or its argument count does not match the selector (so a mis-typed
        function is left untouched).
    """
    name = memory.name_from_ea(decompiled.entry_ea)
    if name is None or not objc.is_objc_method(name):
        return {}
    return _selector_arg_renames(name, decompiled.arguments)


def _selector_arg_renames(name: str, args: list[lvar_t]) -> dict[str, str]:
    """Map each still-default argument's lvar name to the name derived from the selector of `name`."""
    expected_params = name.count(":") + 2
    if len(args) != expected_params:
        return {}

    # "-[Class doFoo:withBar:]" -> ["doFoo", "withBar", ""]
    selector = objc.selector_from_method_name(name) or ""
    keyword_pieces = selector.split(":")

    renames: dict[str, str] = {}
    for pos in range(1, len(args)):  # pos 0 is the receiver (self), left untouched
        default_name = f"a{pos + 1}"
        if args[pos].name != default_name:
            continue  # already carries a meaningful name; don't clobber it
        if pos == 1:
            new_name = "sel"
        elif pos == 2:
            guess = guess_implicit_arg_name(keyword_pieces)
            new_name = naming.camel_to_snake(guess) if guess is not None else "implicit_arg"
        else:
            new_name = naming.camel_to_snake(keyword_pieces[pos - 2])
        renames[default_name] = new_name
    return renames
