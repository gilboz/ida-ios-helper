"""
Long-running IPC server hosted inside `idat`.

Each cold `probe_func.sh` invocation pays 30-90s for `idat` startup, IDB
load, auto-analysis, and plugin imports. When iterating on the plugin
that's a brutal feedback loop. This server runs once per IDB, listens on
a Unix socket, and handles `reload` / `decompile` / `eval` requests from
the host — each request is ~1-2s instead of cold-start time.

Wire: launch with `idat_ipc_launch.sh <binary>`. Drive from the host via
`idat_ipc_client.py`. Verify with `probe_func.sh` (the cold path) only
when work is done.

Protocol: line-delimited JSON over a Unix socket.
    request:  {"op": "<name>", ...}
    response: {"value": ...}  OR  {"error": "..."}

Single-threaded — the main thread blocks on `accept()` and handles each
request synchronously. This matches the hex-rays / IDA threading model
(everything happens on the main thread anyway) and avoids the dance
around `execute_sync` for cross-thread invocation.
"""

import contextlib
import importlib
import json
import os
import socket
import sys
import traceback

import ida_auto
import ida_hexrays
import ida_lines
import idc

DEFAULT_SOCK_PATH = os.environ.get("IOSHELPER_IDAT_SOCK", "/tmp/ioshelper-idat.sock")  # noqa: S108


# Keep references to instantiated hooks / optimizers alive so they don't get GC'd.
_LIVE_HOOKS: list = []
_LIVE_OPTIMIZERS: list = []


def _install_hooks_and_setup() -> None:  # noqa: C901
    """
    Unhook any existing hooks, re-import the plugin modules, install
    fresh hook instances, and run `fix_swift_types()` — honoring the same
    `ioshelper.cfg` gating (features / disabled / experimental components)
    as the GUI plugin core. Safe to call repeatedly — that's the whole
    point of the `reload` command."""
    global _LIVE_HOOKS, _LIVE_OPTIMIZERS
    for h in _LIVE_HOOKS:
        with contextlib.suppress(Exception):
            h.unhook()
    _LIVE_HOOKS = []
    for o in _LIVE_OPTIMIZERS:
        with contextlib.suppress(Exception):
            o.remove()
    _LIVE_OPTIMIZERS = []

    here = os.path.dirname(os.path.abspath(__file__))
    repo_src = os.path.normpath(os.path.join(here, ".."))
    if repo_src not in sys.path:
        sys.path.insert(0, repo_src)

    # Reload every plugin module whose source the user might edit.
    for modname in (
        # idahelper modules the plugin modules below consume — reloaded first so the
        # consumers rebind fresh symbols when they reload in turn.
        "idahelper.runtime",
        "idahelper.naming",
        "idahelper.objc",
        "idahelper.ast.citem",
        # `ast.cexpr` imports `ast.lvars`, so lvars reloads first.
        "idahelper.ast.lvars",
        "idahelper.ast.cexpr",
        # Re-runs `Config.load()`, refreshing the `config` singleton the lvar renamer's
        # per-source gating reads — reloaded before its consumers so they rebind it fresh.
        "ioshelper.base.config",
        # The clang-blocks feature's modules, in dependency order.
        "ioshelper.plugins.common.clang_blocks.model.field_assignments",
        "ioshelper.plugins.common.clang_blocks.model.block_layout",
        "ioshelper.plugins.common.clang_blocks.model.byref_layout",
        "ioshelper.plugins.common.clang_blocks.analyzer.scan",
        "ioshelper.plugins.common.clang_blocks.analyzer.byref_args",
        "ioshelper.plugins.common.clang_blocks.optimizer",
        "ioshelper.plugins.common.clang_blocks.analyzer.options",
        "ioshelper.plugins.common.clang_blocks.analyzer.renamer",
        "ioshelper.plugins.common.clang_blocks.analyzer.pipeline",
        "ioshelper.plugins.swift.swift_types.swift_types",
        "ioshelper.plugins.swift.swift_types.prolog_rewrite",
        "ioshelper.plugins.swift.swift_oslog.log_hook",
        "ioshelper.plugins.objc.objc_sugar.tokens",
        "ioshelper.plugins.objc.objc_sugar.selectors",
        "ioshelper.plugins.objc.objc_sugar.objc_sugar",
        "ioshelper.plugins.objc.objc_sugar.objc_opt",
        "ioshelper.plugins.objc.objc_sugar.objc_msgsend",
        "ioshelper.plugins.objc.objc_msgsend_args.optimizer",
        # The lvar renamer's modules, in dependency order so each re-imports fresh symbols
        # from the ones before it.
        "ioshelper.plugins.objc.objc_lvar_renamer.heuristics",
        "ioshelper.plugins.objc.objc_lvar_renamer.args_source",
        "ioshelper.plugins.objc.objc_lvar_renamer.call_sources",
        "ioshelper.plugins.objc.objc_lvar_renamer.options",
        "ioshelper.plugins.objc.objc_lvar_renamer.renamer",
        "ioshelper.plugins.objc.oslog.os_log",
        "ioshelper.debug.dump_ctree",
        # Reloaded after `dump_ctree` so `dump_ps` re-imports the fresh `dump_ast`.
        "ioshelper.debug.dump_pseudocode",
        "ioshelper.plugins.objc.oslog.log_macro_optimizer",
        "ioshelper.plugins.objc.oslog.log_enabled_optimizer",
        "ioshelper.plugins.objc.oslog.error_case_optimizer",
        "idahelper.dsc.stubs",
        "ioshelper.plugins.dsc.stub_calls.optimizer",
        # Reloaded after `idahelper.dsc.stubs` so the organizer re-imports the fresh
        # `StubSegmentKind`/`stub_segment_kind` symbols it depends on.
        "ioshelper.plugins.dsc.organize_functions.organize_functions",
    ):
        if modname in sys.modules:
            try:
                importlib.reload(sys.modules[modname])
            except Exception as exc:
                print(f"[ipc] reload {modname}: {exc!r}")
        else:
            __import__(modname)

    from ioshelper.base.config import Config, Feature
    from ioshelper.plugins.common.clang_blocks.optimizer import objc_blocks_optimizer_hooks_t
    from ioshelper.plugins.dsc.stub_calls import STUB_CALLS_COMPONENT_NAME
    from ioshelper.plugins.dsc.stub_calls.optimizer import stub_call_optimizer_t
    from ioshelper.plugins.objc.objc_lvar_renamer import OBJC_LVAR_RENAMER_COMPONENT_NAME
    from ioshelper.plugins.objc.objc_lvar_renamer.options import RenamerOptions
    from ioshelper.plugins.objc.objc_lvar_renamer.renamer import ObjcLvarRenameHook
    from ioshelper.plugins.objc.objc_msgsend_args import OBJC_MSGSEND_ARGCOUNT_COMPONENT_NAME
    from ioshelper.plugins.objc.objc_msgsend_args.optimizer import objc_msgsend_argcount_optimizer_t
    from ioshelper.plugins.objc.objc_sugar.objc_msgsend import objc_msgsend_hexrays_hooks_t
    from ioshelper.plugins.objc.objc_sugar.objc_sugar import objc_selector_hexrays_hooks_t
    from ioshelper.plugins.objc.oslog.error_case_optimizer import log_error_case_optimizer_t
    from ioshelper.plugins.objc.oslog.log_enabled_optimizer import os_log_enabled_optimizer_t
    from ioshelper.plugins.objc.oslog.log_macro_optimizer import optimizer as log_macro_optimizer
    from ioshelper.plugins.swift.swift_oslog.log_hook import SwiftLogRewriteHook
    from ioshelper.plugins.swift.swift_types.prolog_rewrite import SwiftPrologRewriteHook
    from ioshelper.plugins.swift.swift_types.swift_types import SwiftClassCallHook, fix_swift_types

    # Re-read the config on every reload so a config edit doesn't need a restart.
    config = Config.load()

    def make_objc_lvar_rename_hook() -> ObjcLvarRenameHook:
        """The renamer hook with its name-source gates resolved, as its component does on load."""
        return ObjcLvarRenameHook(RenamerOptions.load())

    def skip_reason(name: str, feature: Feature | None, *, experimental: bool = False) -> str | None:
        """
        Return why the component `name` should be skipped per `ioshelper.cfg`, or `None` to install it.

        Mirrors the gating in `core.get_modules_for_file`: feature groups, per-component
        disables, and experimental opt-ins."""
        if feature is not None and not config.is_feature_enabled(feature):
            return f"feature {feature.value!r} disabled via disabled_features"
        if not config.is_component_enabled(name):
            return "disabled via disabled_components"
        if experimental and not config.is_experimental_enabled(name):
            return "experimental; enable via experimental_components"
        return None

    # Each spec is (component name, feature, experimental, classes), mirroring the component
    # definitions in each feature's `__init__.py` so the config gates headless installs by
    # the same names as the GUI. Hook order matters — hooks fire in reverse install order:
    # objc-sugar's msgSend hook is listed before its selector hook so it fires after it
    # (match core.objc_plugins order). The objc-lvar-renamer maturity hook uses a different
    # event and is order-independent; its individual name sources are booleans in the
    # config's [objc-lvar-renamer] section, resolved by its factory above. The
    # clang-blocks auto analyzer is GUI-only, so it's not here.
    hook_specs: list[tuple[str, Feature | None, bool, list]] = [
        ("swift-class-call", Feature.SWIFT, False, [SwiftClassCallHook]),
        ("swift-prolog-rewrite", Feature.SWIFT, False, [SwiftPrologRewriteHook]),
        ("swift-oslog", Feature.SWIFT, False, [SwiftLogRewriteHook]),
        # A common component (no feature gate): collapses block field initializations
        # into `_stack_block_init(...)`-style helper calls, like the GUI does.
        ("clang-blocks-optimizer", None, False, [objc_blocks_optimizer_hooks_t]),
        ("objc-sugar", Feature.OBJC, False, [objc_msgsend_hexrays_hooks_t, objc_selector_hexrays_hooks_t]),
        (OBJC_LVAR_RENAMER_COMPONENT_NAME, Feature.OBJC, False, [make_objc_lvar_rename_hook]),
    ]
    for name, feature, experimental, hook_classes in hook_specs:
        reason = skip_reason(name, feature, experimental=experimental)
        if reason is not None:
            print(f"[ipc] skipping hook component {name!r}: {reason}")
            continue
        for cls in hook_classes:
            try:
                h = cls()
                if h is None:
                    print(f"[ipc] skipping hook component {name!r}: option-gated factory returned None")
                    continue
                h.hook()
                _LIVE_HOOKS.append(h)
            except Exception as exc:
                print(f"[ipc] install {getattr(cls, '__name__', repr(cls))}: {exc!r}")
    # Microcode optimizers: headless `idat` doesn't auto-install the plugin's
    # `optinsn_t`/`optblock_t` optimizers, so instantiate the ones whose output the
    # probe needs to reflect. The DSC stub retargeting exposes the clean callee names
    # the os_log matchers rely on. Install order is not load-bearing for optinsn_t:
    # any change reruns the optimizers.
    optimizer_specs: list[tuple[str, Feature | None, bool, list]] = [
        (STUB_CALLS_COMPONENT_NAME, None, True, [stub_call_optimizer_t]),
        (
            "oslog-optimizer",
            Feature.OBJC,
            False,
            [log_error_case_optimizer_t, os_log_enabled_optimizer_t, log_macro_optimizer],
        ),
        (OBJC_MSGSEND_ARGCOUNT_COMPONENT_NAME, Feature.OBJC, True, [objc_msgsend_argcount_optimizer_t]),
    ]
    for name, feature, experimental, optimizer_classes in optimizer_specs:
        reason = skip_reason(name, feature, experimental=experimental)
        if reason is not None:
            print(f"[ipc] skipping optimizer component {name!r}: {reason}")
            continue
        for opt_cls in optimizer_classes:
            try:
                o = opt_cls()
                o.install()
                _LIVE_OPTIMIZERS.append(o)
            except Exception as exc:
                print(f"[ipc] install {opt_cls.__name__}: {exc!r}")
    # `fix_swift_types` is the `swift-types` StartupScript component in the GUI.
    reason = skip_reason("swift-types", Feature.SWIFT)
    if reason is not None:
        print(f"[ipc] skipping startup component 'swift-types': {reason}")
    else:
        try:
            fix_swift_types()
        except Exception as exc:
            print(f"[ipc] fix_swift_types: {exc!r}")
    # Invalidate every cached cfunc so subsequent `decompile` calls don't
    # serve stale pseudo from before the reload.
    with contextlib.suppress(Exception):
        ida_hexrays.clear_cached_cfuncs()


def _coerce_ea(ea) -> int:
    if isinstance(ea, int):
        return ea
    if isinstance(ea, str):
        return int(ea, 0)
    raise ValueError(f"bad ea: {ea!r}")


def _decompile(ea_raw, sections: list[str] | None = None, passes: int = 3) -> str:
    """
    Decompile `ea` and return the requested sections joined with `\\n`.
    Defaults to 3 passes — the maturity hook applies types during pass 1's
    decompile, the post-print invalidation fires after pass 2's storage,
    and pass 3 sees the fully-typed prototype in the rendered header.
    This gets the GUI-equivalent multi-F5 behavior cheaply.
    """
    ea = _coerce_ea(ea_raw)
    sections = sections or ["pseudo"]
    cfunc = None
    for _ in range(max(1, passes)):
        ida_hexrays.mark_cfunc_dirty(ea, False)
        # DECOMP_NO_CACHE forces a fresh build per request — the cfunc
        # cache otherwise serves a snapshot that doesn't pick up the
        # prototype change applied in the previous pass's maturity hook.
        cfunc = ida_hexrays.decompile(ea, None, ida_hexrays.DECOMP_NO_CACHE)
        if cfunc is None:
            return f"[ipc] decompile({ea:#x}) returned None"
    out: list[str] = []
    out.append(f"=== {ea:#x} type ===")
    out.append(idc.get_type(ea) or "(no stored type)")
    if "pseudo" in sections:
        out.append("=== pseudo ===")
        sv = cfunc.get_pseudocode()
        for i in range(sv.size()):
            out.append(ida_lines.tag_remove(sv[i].line))
    if "lvars" in sections:
        out.append("=== lvars ===")
        lvars = cfunc.get_lvars()
        for i in range(lvars.size()):
            lv = lvars[i]
            try:
                t = str(lv.type())
            except Exception:
                t = "?"
            out.append(f"  [{i}] {lv.name}: {t}")
    # Imported lazily so `reload` serves the freshly re-imported dump code.
    if "ast" in sections:
        from ioshelper.debug.dump_ctree import dump_ast

        out.append("=== ast ===")
        out.append(dump_ast(cfunc))
    if "calls" in sections:
        from ioshelper.debug.dump_ctree import dump_calls

        out.append("=== calls ===")
        out.append(dump_calls(cfunc))
    return "\n".join(out)


def _eval_code(code: str):
    """
    Run `code` in a namespace that has common IDA modules pre-imported.
    Tries `eval` first (for one-liners); falls back to `exec` (which
    supports statements, multi-line, imports). `exec` returns None — to
    surface a value, assign to `_` and the caller will print it."""
    import ida_funcs
    import ida_idp
    import ida_nalt
    import ida_typeinf
    import idaapi

    ns: dict = {
        "ida_hexrays": ida_hexrays,
        "ida_funcs": ida_funcs,
        "ida_idp": ida_idp,
        "ida_nalt": ida_nalt,
        "ida_typeinf": ida_typeinf,
        "idaapi": idaapi,
        "idc": idc,
    }
    try:
        return eval(code, ns)  # noqa: S307
    except SyntaxError:
        import io
        from contextlib import redirect_stdout

        buf = io.StringIO()
        with redirect_stdout(buf):
            exec(code, ns)  # noqa: S102
        out = buf.getvalue()
        if "_" in ns and ns["_"] is not None:
            return ns["_"]
        return out


def _handle_command(cmd: dict) -> dict:
    op = cmd.get("op")
    if op == "ping":
        return {"value": "pong"}
    if op == "decompile":
        return {"value": _decompile(cmd.get("ea"), cmd.get("sections"), cmd.get("passes", 2))}
    if op == "reload":
        _install_hooks_and_setup()
        return {"value": "reloaded"}
    if op == "eval":
        code = cmd.get("code", "")
        result = _eval_code(code)
        return {"value": repr(result)}
    if op == "quit":
        return {"value": "bye", "__quit__": True}
    return {"error": f"unknown op: {op!r}"}


def _serve(sock_path: str) -> None:  # noqa: C901
    if os.path.exists(sock_path):
        os.unlink(sock_path)
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    srv.bind(sock_path)
    srv.listen(1)
    print(f"[ipc] listening on {sock_path}")
    while True:
        conn, _ = srv.accept()
        try:
            buf = b""
            while b"\n" not in buf:
                chunk = conn.recv(65536)
                if not chunk:
                    break
                buf += chunk
            if not buf:
                continue
            line = buf.split(b"\n", 1)[0]
            try:
                cmd = json.loads(line.decode("utf-8"))
            except Exception as exc:
                resp = {"error": f"parse: {exc!r}"}
            else:
                try:
                    resp = _handle_command(cmd)
                except Exception:
                    resp = {"error": traceback.format_exc()}
            should_quit = resp.pop("__quit__", False)
            with contextlib.suppress(Exception):
                conn.sendall(json.dumps(resp).encode("utf-8") + b"\n")
            if should_quit:
                conn.close()
                break
        finally:
            with contextlib.suppress(Exception):
                conn.close()
    try:
        srv.close()
        os.unlink(sock_path)
    except Exception:  # noqa: S110
        pass


def main() -> None:
    ida_auto.auto_wait()
    if not ida_hexrays.init_hexrays_plugin():
        print("[ipc] hex-rays not available")
        idc.qexit(1)
    _install_hooks_and_setup()
    try:
        _serve(DEFAULT_SOCK_PATH)
    finally:
        idc.qexit(0)


main()
