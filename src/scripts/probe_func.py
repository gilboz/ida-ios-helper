"""
Headless IDA probe: dump everything about a function that's useful when
iterating on a hex-rays plugin — pseudocode, lvars, ctree AST, and microcode
at multiple maturities — so the loop can be driven from a shell without a
human staring at IDA's GUI.

Designed to be invoked via the companion `probe_func.sh` wrapper, but works
standalone as:

    idat -A -Sprobe_func.py" 0x10001A41C [section ...] -Lout.txt path/to/idb

Sections (any subset; default is all):
    pseudo   - the decompiled pseudocode
    lvars    - lvar table (idx, name, type, flags)
    ast      - cinsn_t/cexpr_t tree dump with op names
    calls    - every call in the function (name + arg shapes)
    mc       - microcode at MMAT_CALLS and MMAT_GLBOPT3

Each section is delimited so a shell consumer can grep/awk it out.
"""

import contextlib
import sys
from typing import TYPE_CHECKING

import ida_auto
import ida_funcs
import ida_hexrays
import ida_lines
import idc

if TYPE_CHECKING:
    from ioshelper.base.config import Config, Feature

_DEFAULT_SECTIONS = ("pseudo", "lvars", "ast", "calls", "mc")


def _banner(title: str) -> None:
    print(f"\n=== {title} " + "=" * (60 - len(title)))


def _end(title: str) -> None:
    print(f"--- end {title} " + "-" * (56 - len(title)))


def _strip_tags(line: str) -> str:
    return ida_lines.tag_remove(line) or line


# --- pseudocode -------------------------------------------------------------


def dump_pseudocode(cfunc: ida_hexrays.cfunc_t) -> None:
    _banner(f"PSEUDOCODE @ {cfunc.entry_ea:#x}")
    sv = cfunc.get_pseudocode()
    for line in sv:
        print(_strip_tags(line.line))
    _end("PSEUDOCODE")


# --- lvars ------------------------------------------------------------------


def dump_lvars(cfunc: ida_hexrays.cfunc_t) -> None:
    _banner("LVARS")
    lvars = cfunc.get_lvars()
    for i in range(lvars.size()):
        lv = lvars[i]
        try:
            t = str(lv.type())
        except Exception:
            t = "?"
        flags = []
        if lv.has_user_name:
            flags.append("user_name")
        if lv.has_user_type:
            flags.append("user_type")
        if lv.is_arg_var:
            flags.append("arg")
        flag_str = ",".join(flags) or "-"
        print(f"  [{i:3d}] {lv.name:<26s} {t:<34s} {flag_str}")
    _end("LVARS")


# --- AST / calls (shared with the IPC server via ioshelper.debug.dump_ctree) --


def dump_ast(cfunc: ida_hexrays.cfunc_t) -> None:
    # Imported lazily: `_install_ioshelper_hooks` has put the repo's src/ on sys.path by now.
    from ioshelper.debug.dump_ctree import dump_ast as dump_ast_text

    _banner("AST")
    print(dump_ast_text(cfunc))
    _end("AST")


def dump_calls(cfunc: ida_hexrays.cfunc_t) -> None:
    from ioshelper.debug.dump_ctree import dump_calls as dump_calls_text

    _banner("CALLS")
    print(dump_calls_text(cfunc))
    _end("CALLS")


# --- microcode --------------------------------------------------------------


_MATURITY_LEVELS = [
    ("MMAT_GENERATED", "MMAT_GENERATED"),
    ("MMAT_PREOPTIMIZED", "MMAT_PREOPTIMIZED"),
    ("MMAT_LOCOPT", "MMAT_LOCOPT"),
    ("MMAT_CALLS", "MMAT_CALLS"),
    ("MMAT_GLBOPT1", "MMAT_GLBOPT1"),
    ("MMAT_GLBOPT2", "MMAT_GLBOPT2"),
    ("MMAT_GLBOPT3", "MMAT_GLBOPT3"),
    ("MMAT_LVARS", "MMAT_LVARS"),
]


def dump_microcode(func_ea: int, maturities: list[str]) -> None:
    func = ida_funcs.get_func(func_ea)
    if func is None:
        _banner("MICROCODE")
        print(f"(no function at {func_ea:#x})")
        _end("MICROCODE")
        return

    for label in maturities:
        mat_value = getattr(ida_hexrays, label, None)
        if mat_value is None:
            continue
        _banner(f"MICROCODE @ {label}")
        mbr = ida_hexrays.mba_ranges_t(func)
        hf = ida_hexrays.hexrays_failure_t()
        mba = ida_hexrays.gen_microcode(mbr, hf, None, 0, mat_value)
        if mba is None:
            print(f"(gen_microcode failed: {hf.desc()})")
            _end(f"MICROCODE @ {label}")
            continue

        class P(ida_hexrays.vd_printer_t):
            def _print(self, _indent, line):
                print(_strip_tags(line))
                return 1

        mba._print(P())
        _end(f"MICROCODE @ {label}")


# --- driver -----------------------------------------------------------------


def _parse_args() -> tuple[int, list[str], list[str]]:
    raw = list(getattr(idc, "ARGV", []) or [])
    if not raw:
        raw = list(sys.argv)
    # Drop the leading script name + any empty strings (shell quoting artifacts).
    args = [a for a in raw[1:] if a]
    if not args:
        print("[probe] usage: probe_func.py <ea> [section ...]", file=sys.stderr)
        idc.qexit(1)
    ea_str = args[0]
    ea = int(ea_str, 16) if ea_str.lower().startswith("0x") else int(ea_str, 0)
    sections = args[1:] if len(args) > 1 else list(_DEFAULT_SECTIONS)
    # Allow `--all` to mean every section + every microcode maturity.
    mc_levels = ["MMAT_CALLS", "MMAT_GLBOPT3"]
    if "--all-mc" in sections:
        sections = [s for s in sections if s != "--all-mc"]
        mc_levels = [name for name, _ in _MATURITY_LEVELS]
    return ea, sections, mc_levels


# Keep references to instantiated hooks / optimizers alive so they don't get garbage-collected.
_LIVE_HOOKS: list = []
_LIVE_OPTIMIZERS: list = []


def _component_skip_reason(
    config: "Config", name: str, feature: "Feature | None", *, experimental: bool = False
) -> str | None:
    """
    Return why the component `name` should be skipped per `ioshelper.cfg`, or `None` to install it.

    Mirrors the gating in `core.get_modules_for_file`: feature groups, per-component
    disables, and experimental opt-ins.

    Args:
        config: The parsed `ioshelper.cfg`.
        name: The component's name, as used by `disabled_components`/`experimental_components`.
        feature: The feature group the component belongs to, or `None` for ungrouped ones.
        experimental: Whether the component requires an `experimental_components` opt-in.

    Returns:
        A human-readable skip reason, or `None` when the component should be installed.
    """
    if feature is not None and not config.is_feature_enabled(feature):
        return f"feature {feature.value!r} disabled via disabled_features"
    if not config.is_component_enabled(name):
        return "disabled via disabled_components"
    if experimental and not config.is_experimental_enabled(name):
        return "experimental; enable via experimental_components"
    return None


def _install_ioshelper_hooks() -> None:
    """
    Headless idat skips installing Hexrays_Hooks subclasses that the plugin
    registers, so we instantiate + `.hook()` each one ourselves, honoring the
    same `ioshelper.cfg` gating (features / disabled / experimental components)
    as the GUI plugin core. Easier than teaching reloadable_plugin to also run
    in headless mode."""
    import os

    here = os.path.dirname(os.path.abspath(__file__))
    repo_src = os.path.normpath(os.path.join(here, ".."))
    if repo_src not in sys.path:
        sys.path.insert(0, repo_src)

    try:
        from ioshelper.base.config import Config, Feature
        from ioshelper.plugins.common.clang_blocks.optimizer import objc_blocks_optimizer_hooks_t
        from ioshelper.plugins.objc.objc_lvar_renamer import OBJC_LVAR_RENAMER_COMPONENT_NAME
        from ioshelper.plugins.objc.objc_lvar_renamer.options import RenamerOptions
        from ioshelper.plugins.objc.objc_lvar_renamer.renamer import ObjcLvarRenameHook
        from ioshelper.plugins.swift.swift_oslog.log_hook import SwiftLogRewriteHook
        from ioshelper.plugins.swift.swift_types.prolog_rewrite import SwiftPrologRewriteHook
        from ioshelper.plugins.swift.swift_types.swift_types import SwiftClassCallHook
    except Exception as exc:
        print(f"[probe] failed to import hooks: {exc!r}", file=sys.stderr)
        return

    config = Config.load()

    def make_objc_lvar_rename_hook() -> ObjcLvarRenameHook:
        """The renamer hook with its name-source gates resolved, as its component does on load."""
        return ObjcLvarRenameHook(RenamerOptions.load())

    # Each spec is (component name, feature, experimental, hook factory), mirroring the
    # component definitions in each feature's `__init__.py` so the config gates the
    # probe's installs by the same names as the GUI. The objc-lvar-renamer's individual
    # name sources are booleans in the config's [objc-lvar-renamer] section, resolved by
    # its factory above. The clang-blocks auto analyzer is GUI-only, so it's not here.
    hook_specs = [
        ("swift-class-call", Feature.SWIFT, False, SwiftClassCallHook),
        ("swift-prolog-rewrite", Feature.SWIFT, False, SwiftPrologRewriteHook),
        ("swift-oslog", Feature.SWIFT, False, SwiftLogRewriteHook),
        # A common component (no feature gate): collapses block field initializations
        # into `_stack_block_init(...)`-style helper calls, like the GUI does.
        ("clang-blocks-optimizer", None, False, objc_blocks_optimizer_hooks_t),
        (OBJC_LVAR_RENAMER_COMPONENT_NAME, Feature.OBJC, False, make_objc_lvar_rename_hook),
    ]
    for name, feature, experimental, hook_factory in hook_specs:
        _install_one_hook(config, name, feature, experimental, hook_factory)

    _run_swift_types_startup(config)
    _install_ioshelper_optimizers(config)


def _install_one_hook(config: "Config", name: str, feature, experimental: bool, hook_factory) -> None:
    """Instantiate and hook one headless Hexrays hook, honoring config gates."""
    reason = _component_skip_reason(config, name, feature, experimental=experimental)
    if reason is not None:
        print(f"[probe] skipping hook component {name!r}: {reason}")
        return
    try:
        h = hook_factory()
        if h is None:
            print(f"[probe] skipping hook component {name!r}: option-gated factory returned None")
            return
        ok = h.hook()
        _LIVE_HOOKS.append(h)
        print(f"[probe] installed {type(h).__name__} hook ok={ok}")
    except Exception as exc:
        print(f"[probe] {hook_factory.__name__} install failed: {exc!r}", file=sys.stderr)


def _run_swift_types_startup(config: "Config") -> None:
    """Run the `swift-types` startup script that headless idat also skips."""
    from ioshelper.base.config import Feature

    reason = _component_skip_reason(config, "swift-types", Feature.SWIFT)
    if reason is not None:
        print(f"[probe] skipping startup component 'swift-types': {reason}")
        return
    try:
        from ioshelper.plugins.swift.swift_types.swift_types import fix_swift_types

        fix_swift_types()
        print("[probe] ran fix_swift_types()")
    except Exception as exc:
        print(f"[probe] fix_swift_types failed: {exc!r}", file=sys.stderr)


def _install_ioshelper_optimizers(config: "Config") -> None:
    """
    Install the plugin's microcode optimizers, which headless idat also skips.

    Covers the os_log optimizers plus the DSC stub retargeting that exposes the clean
    callee names the os_log matchers rely on (install order is not load-bearing:
    optinsn_t optimizers rerun after any change). Each optimizer is gated by the same
    `ioshelper.cfg` component names as the GUI.

    Args:
        config: The parsed `ioshelper.cfg`.
    """
    try:
        from ioshelper.base.config import Feature
        from ioshelper.plugins.dsc.stub_calls import STUB_CALLS_COMPONENT_NAME
        from ioshelper.plugins.dsc.stub_calls.optimizer import stub_call_optimizer_t
        from ioshelper.plugins.objc.oslog.error_case_optimizer import log_error_case_optimizer_t
        from ioshelper.plugins.objc.oslog.log_enabled_optimizer import os_log_enabled_optimizer_t
        from ioshelper.plugins.objc.oslog.log_macro_optimizer import optimizer as log_macro_optimizer
    except Exception as exc:
        print(f"[probe] failed to import optimizers: {exc!r}", file=sys.stderr)
        return

    optimizer_specs = [
        (STUB_CALLS_COMPONENT_NAME, None, True, [stub_call_optimizer_t]),
        (
            "oslog-optimizer",
            Feature.OBJC,
            False,
            [log_error_case_optimizer_t, os_log_enabled_optimizer_t, log_macro_optimizer],
        ),
    ]
    for name, feature, experimental, factories in optimizer_specs:
        reason = _component_skip_reason(config, name, feature, experimental=experimental)
        if reason is not None:
            print(f"[probe] skipping optimizer component {name!r}: {reason}")
            continue
        for factory in factories:
            try:
                o = factory()
                o.install()
                _LIVE_OPTIMIZERS.append(o)
                print(f"[probe] installed {factory.__name__} optimizer")
            except Exception as exc:
                print(f"[probe] {factory.__name__} install failed: {exc!r}", file=sys.stderr)


def _decompile_target(ea: int):
    """Fresh-decompile `ea`."""
    with contextlib.suppress(Exception):
        ida_hexrays.mark_cfunc_dirty(ea, False)
    return ida_hexrays.decompile(ea)


def main() -> None:
    ida_auto.auto_wait()

    if not ida_hexrays.init_hexrays_plugin():
        print("[probe] hex-rays not available", file=sys.stderr)
        idc.qexit(1)

    ea, sections, mc_levels = _parse_args()
    print(f"[probe] target ea={ea:#x} sections={sections} mc={mc_levels}")

    # In headless mode IDA loads the plugin but doesn't auto-install its
    # Hexrays_Hooks subclasses. Instantiate + hook them explicitly so the
    # decompile we're about to do triggers them.
    _install_ioshelper_hooks()

    cfunc = _decompile_target(ea)
    if cfunc is None:
        print(f"[probe] decompile({ea:#x}) failed", file=sys.stderr)
        idc.qexit(1)

    if "pseudo" in sections:
        dump_pseudocode(cfunc)
    if "lvars" in sections:
        dump_lvars(cfunc)
    if "ast" in sections:
        dump_ast(cfunc)
    if "calls" in sections:
        dump_calls(cfunc)
    if "mc" in sections:
        dump_microcode(ea, mc_levels)

    print("[probe] done")
    idc.qexit(0)


if __name__ == "__main__":
    main()
