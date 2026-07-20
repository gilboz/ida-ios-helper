"""
Selector-text -> variable-name heuristics shared by the renamer's name sources.

Pure string processing: nothing here touches the ctree or the lvars, so every name
source draws its vocabulary of naming rules (verbs, prepositions, delegate callbacks,
getter shapes) from one place.
"""

__all__ = [
    "DEFAULT_LVAR_NAME",
    "getter_name",
    "guess_implicit_arg_name",
    "to_snake_identifier",
]

import re

from idahelper import naming

# Only hex-rays' default names (`a3` arguments, `v12` locals) are ever renamed -- never
# stack slots (`_18`) or anything a user or an IDA heuristic already named.
DEFAULT_LVAR_NAME = re.compile(r"^[av]\d+$")

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

# Zero-argument selectors that return an object which is not a property value -- naming a
# local `copy` / `new` after one would mislead, so they are not treated as getters.
_NON_GETTER_SELECTORS = frozenset({
    "alloc", "init", "new", "copy", "mutableCopy", "retain", "release",
    "autorelease", "dealloc", "load", "self", "class",
})  # fmt: skip

# A leading `get` before a camel word: `getTitle` -> `Title`, but `get` alone is left as-is.
_GET_PREFIX = re.compile(r"^get(?=[A-Z])")
_IDENTIFIER = re.compile(r"^[A-Za-z_]\w*$")


def guess_implicit_arg_name(keyword_pieces: list[str]) -> str | None:
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


def getter_name(selector: str) -> str | None:
    """Derive a snake_case name from a zero-argument getter selector, or `None` to skip it."""
    if not selector or ":" in selector or selector in _NON_GETTER_SELECTORS:
        return None
    return to_snake_identifier(_GET_PREFIX.sub("", selector))


def to_snake_identifier(camel: str) -> str | None:
    """Lower `camel` to snake_case, or `None` if the result is not a usable identifier."""
    if not camel:
        return None
    snake = naming.camel_to_snake(camel)
    return snake if _IDENTIFIER.match(snake) else None
