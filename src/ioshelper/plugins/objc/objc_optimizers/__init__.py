__all__ = ["component"]

import idaapi

from ioshelper.base.reloadable_plugin import OptimizersComponent, optimizer_factory_t

from .objc_arc import objc_arc_optimizer_t
from .objc_calls import objc_calls_optimizer_t
from .objc_properties import objc_properties_optimizer_t

# IDA 9.4 beta 1 (IDA_SDK_VERSION == 940) added a built-in "hide Obj-C ARC calls" feature that
# folds the canonical retain/release/autorelease/claim helpers to mov/nop itself. On those builds
# we step aside and let IDA own ARC visibility (toggled from its own menu); on older IDA we keep
# folding them ourselves. The non-ARC folds (properties, blocks, Swift bridge) run on every version.
#
# Headless (idalib) ARC visibility is governed by OBJC_ARC_SHOW plus a persisted per-IDB netnode,
# not by this code; see docs/objc-arc-headless-idalib.md.
_IDA_HAS_BUILTIN_ARC = idaapi.IDA_SDK_VERSION >= 940

_optimizers: list[optimizer_factory_t] = [objc_properties_optimizer_t, objc_calls_optimizer_t]
if not _IDA_HAS_BUILTIN_ARC:
    _optimizers.append(objc_arc_optimizer_t)

component = OptimizersComponent.factory("Obj-C optimizers", _optimizers)
