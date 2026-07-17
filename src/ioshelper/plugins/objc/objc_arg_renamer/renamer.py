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
user-applied prototype are preserved.
"""

__all__ = [
    "rename_objc_method_args",
    "rename_objc_method_args_during_decompilation",
]

import re

from ida_funcs import func_t
from ida_hexrays import DecompilationFailure, cfunc_t, lvar_t
from idahelper import memory, naming, objc
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

# Verbs that move a thing to a place: `add <X> to <Y>`. For these, in `addAmountToBalance:`
# the argument is the verb's object (`Amount`, the thing added), while `ToBalance` only names
# the destination — the reverse of what the general preposition rule would pick. Kept narrow
# on purpose: property accessors (`set`/`get`) are excluded because their `XToY` is usually a
# single property name (`setFitToWidth:` sets `fitToWidth`), and source `from` is excluded
# because there the argument *is* the source (`copyPropertiesFromBuffer:` -> `Buffer`).
_TRANSFER_VERBS = (
    "add", "insert", "append", "push", "enqueue", "send", "post", "write", "save", "copy", "move", "apply",
)  # fmt: skip
# Destination markers written as whole camel words (so the `To` in `AmountToBalance` matches
# but the `to` inside `Photo`/`Auto` does not). Case-sensitive on purpose.
_DESTINATION_WORDS = ("To", "Into", "Onto")

# The keyword wording is matched case-insensitively (developers are not always consistent),
# but the captured argument name must start a camel word (an uppercase letter).
_PREPOSITION_SUFFIX = re.compile(rf".*(?i:{'|'.join(_PREPOSITIONS)})([A-Z][A-Za-z0-9]*)$")
_VERB_PREFIX = re.compile(rf"(?i:{'|'.join(_VERBS)})([A-Z][A-Za-z0-9]*)$")
# A transfer verb's object sitting before a destination word: `add` `Amount` `To` `Balance`.
# The object is captured non-greedily so it stops at the first destination word, which must
# itself begin a new camel word (be followed by an uppercase letter).
_VERB_OBJECT_BEFORE_DESTINATION = re.compile(
    rf"(?i:{'|'.join(_TRANSFER_VERBS)})([A-Z][A-Za-z0-9]*?)(?:{'|'.join(_DESTINATION_WORDS)})[A-Z]"
)


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

    modifications = _selector_arg_modifications(name, decompiled.arguments)
    if not modifications:
        return False
    return lvars.perform_lvar_modifications(func.start_ea, decompiled.get_lvars(), modifications)


def rename_objc_method_args_during_decompilation(decompiled: cfunc_t) -> bool:
    """
    Rename the arguments of the in-flight decompilation `decompiled` based on its selector.

    For use inside a decompilation event (e.g. a `maturity` hook): the renames are written
    through the saved-settings fast path and patched onto the live `lvar_t`s, so no extra
    decompilation is triggered.

    Args:
        decompiled: The function's in-flight decompilation.

    Returns:
        `True` if the function is an Obj-C method and at least one argument was renamed.
    """
    name = memory.name_from_ea(decompiled.entry_ea)
    if name is None or not objc.is_objc_method(name):
        return False

    modifications = _selector_arg_modifications(name, decompiled.arguments)
    if not modifications:
        return False
    return lvars.perform_lvar_modifications_during_decompilation(
        decompiled.entry_ea, decompiled.get_lvars(), modifications
    )


def _selector_arg_modifications(name: str, args: list[lvar_t]) -> dict[str, VariableModification]:
    """Build the rename modifications for the still-default arguments of the method named `name`."""
    renames = _selector_arg_renames(name, args)
    return {old: VariableModification(name=new) for old, new in renames.items()}


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
    * Transfer verb object before a destination -- the object of a leading transfer verb
      (`add`/`send`/`copy`/...) that sits before a `To`/`Into`/`Onto` destination:
      `addAmountToBalance:` -> `Amount` (the thing added), not `Balance` (where it goes).
      Checked before the general preposition rule, which would otherwise pick the destination.
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
    if (match := _VERB_OBJECT_BEFORE_DESTINATION.match(first_piece)) is not None:
        return match.group(1)
    if (match := _PREPOSITION_SUFFIX.match(first_piece)) is not None:
        return match.group(1)
    if (match := _VERB_PREFIX.match(first_piece)) is not None:
        return match.group(1)
    return None
