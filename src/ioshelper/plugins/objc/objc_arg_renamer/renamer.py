"""
Rename the default-named arguments of Obj-C methods from their selector.

For a method named `-[Class doFoo:withBar:]` / `+[Class ...]` the decompiler's default
`a1`, `a2` ... arguments are renamed to mirror the Obj-C calling layout:

    a1 -> self          (the receiver, left untouched)
    a2 -> sel           (the selector / _cmd)
    a3 -> a name guessed from the selector (`initWithFrame:` -> `frame`,
          `tableView:didSelectRowAtIndexPath:` -> `table_view`), falling back to `implicit_arg`
    a4+ -> selector keyword pieces

All derived names are converted to snake_case.

The current names are read from the decompiled function's argument lvars: only arguments
that still carry their default `aN` name are touched, so manual renames and names from a
user-applied prototype are preserved. `rename_all_objc_method_args` drives this across the
whole database.
"""

__all__ = ["rename_all_objc_method_args", "rename_objc_method_args"]

import re

from ida_funcs import func_t
from ida_hexrays import DecompilationFailure, lvar_t
from idahelper import functions, memory, naming, objc
from idahelper.ast import cfunc, lvars
from idahelper.ast.lvars import VariableModification

# The implicit argument follows one of these words: `initWithFrame:` -> `Frame`.
_PREPOSITIONS = ("with", "for", "at", "from", "to", "of", "in", "by", "using")
# The implicit argument is the object of one of these leading verbs: `addObject:` -> `Object`.
_VERBS = (
    "set", "get", "add", "remove", "insert", "append", "register", "unregister", "send", "post",
    "handle", "process", "parse", "load", "save", "write", "read", "encode", "decode", "apply",
    "update", "perform", "present", "dismiss", "show", "hide", "cancel", "push", "pop", "enqueue", "dequeue",
)  # fmt: skip
# Second selector piece of a delegate callback, where the first piece names the sender.
_DELEGATE_PREFIXES = ("did", "will", "should")

# The keyword wording is matched case-insensitively (developers are not always consistent),
# but the captured argument name must start a camel word (an uppercase letter).
_PREPOSITION_SUFFIX = re.compile(rf".*(?i:{'|'.join(_PREPOSITIONS)})([A-Z][A-Za-z0-9]*)$")
_VERB_PREFIX = re.compile(rf"(?i:{'|'.join(_VERBS)})([A-Z][A-Za-z0-9]*)$")


def rename_all_objc_method_args() -> None:
    """Rename the default-named arguments of every Obj-C method in the database."""
    count = 0
    for func in functions.iterate_functions():
        if rename_objc_method_args(func):
            count += 1
    print(f"[Info] Renamed arguments for {count} Obj-C methods")


def rename_objc_method_args(func: func_t) -> bool:
    """
    Rename the arguments of the Obj-C method at `func` based on its selector.

    Args:
        func: The function to rename the arguments of.

    Returns:
        `True` if the function is an Obj-C method and at least one argument was renamed.
    """
    name = memory.name_from_ea(func.start_ea)
    if name is None or not objc.is_objc_method(name):
        return False

    try:
        decompiled = cfunc.from_func(func)
    except DecompilationFailure as e:
        print(f"[Error] Failed to decompile function {func.start_ea}: {e}")
        return False
    if decompiled is None:
        return False

    renames = _selector_arg_renames(name, decompiled.arguments)
    if not renames:
        return False

    modifications = {old: VariableModification(name=new) for old, new in renames.items()}
    return lvars.perform_lvar_modifications(func.start_ea, decompiled.get_lvars(), modifications)


def _selector_arg_renames(name: str, args: list[lvar_t]) -> dict[str, str]:
    """
    Map each still-default argument's lvar name to the name derived from the selector.

    Returns an empty mapping when the function's argument count does not match the
    selector (so a mis-typed function is left untouched).
    """
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
            guess = _guess_implicit_arg_name(keyword_pieces)
            new_name = naming.camel_to_snake(guess) if guess is not None else "implicit_arg"
        else:
            new_name = naming.camel_to_snake(keyword_pieces[pos - 2])
        renames[default_name] = new_name
    return renames


def _guess_implicit_arg_name(keyword_pieces: list[str]) -> str | None:
    """
    Guess a name for the argument carried by the first selector piece.

    The first piece of a selector is the method name itself, so its argument has no keyword
    of its own. Common naming patterns still encode it:

    * Delegate callbacks -- when the second piece starts with `did`/`will`/`should`, the
      first piece names the sender: `tableView:didSelectRowAtIndexPath:` -> `tableView`.
    * Prepositions -- the words after the last `with`/`for`/`at`/... : `initWithFrame:` -> `Frame`.
    * Leading verbs -- the object of `set`/`add`/`remove`/... : `addObserver:` -> `Observer`.

    Args:
        keyword_pieces: The selector split on `:`, e.g. `["initWithFrame", ""]`.

    Returns:
        The guessed name in the piece's original camelCase, or `None` when no pattern matches.
    """
    first_piece = keyword_pieces[0]
    if not first_piece:
        return None
    if len(keyword_pieces) > 1 and keyword_pieces[1].lower().startswith(_DELEGATE_PREFIXES):
        return first_piece
    if (match := _PREPOSITION_SUFFIX.match(first_piece)) is not None:
        return match.group(1)
    if (match := _VERB_PREFIX.match(first_piece)) is not None:
        return match.group(1)
    return None
