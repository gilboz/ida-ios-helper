"""
Rename the default-named arguments of Obj-C methods from their selector.

For a method named `-[Class doFoo:withBar:]` / `+[Class ...]` the decompiler's default
`a1`, `a2` ... arguments are renamed to mirror the Obj-C calling layout:

    a1 -> self          (the receiver, left untouched)
    a2 -> sel           (the selector / _cmd)
    a3 -> implicitArg
    a4+ -> selector keyword pieces

Only arguments that still carry their default name are touched, so manual renames are
preserved. `rename_all_objc_method_args` drives this across the whole database.
"""

__all__ = ["rename_all_objc_method_args", "rename_objc_method_args"]

from ida_funcs import func_t
from ida_typeinf import func_type_data_t
from idahelper import functions, memory, objc, tif
from idahelper.ast import lvars
from idahelper.ast.lvars import VariableModification


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

    details = tif.get_func_details(func)
    if details is None:
        return False

    renames = _selector_arg_renames(name, details)
    if not renames:
        return False

    modifications = {old: VariableModification(name=new) for old, new in renames.items()}
    return lvars.perform_lvar_modifications_by_ea(func.start_ea, modifications)


def _selector_arg_renames(name: str, details: func_type_data_t) -> dict[str, str]:
    """
    Map each still-default argument name to the name derived from the selector.

    Returns an empty mapping when the function's parameter count does not match the
    selector (so a mis-typed function is left untouched).
    """
    expected_params = name.count(":") + 2
    if len(details) != expected_params:
        return {}

    # "-[Class doFoo:withBar:]" -> ["doFoo", "withBar", ""]
    keyword_pieces = name.split(" ")[1].split("]")[0].split(":")

    renames: dict[str, str] = {}
    for pos in range(1, len(details)):  # pos 0 is the receiver (self), left untouched
        default_name = f"a{pos + 1}"
        if (details[pos].name or default_name) != default_name:
            continue  # already carries a meaningful name; don't clobber it
        if pos == 1:
            new_name = "sel"
        elif pos == 2:
            new_name = "implicitArg"
        else:
            new_name = keyword_pieces[pos - 2]
        renames[default_name] = new_name
    return renames
