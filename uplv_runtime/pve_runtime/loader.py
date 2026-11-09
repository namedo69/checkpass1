"""Load authenticated vendor bytecode without shadowing application modules."""
import builtins
import hashlib
import importlib.util
import json
import marshal
import sys
import threading
import types
from pathlib import Path

ROOT = Path(__file__).resolve().parent / "vendor"
_LOCK = threading.RLock()
_MODULES = {}
_MANIFEST = None


def load(name):
    global _MANIFEST
    with _LOCK:
        if _MANIFEST is None:
            _MANIFEST = json.loads((ROOT / "manifest.json").read_text(encoding="utf-8"))
            if list(sys.version_info[:2]) != _MANIFEST["python"]:
                raise RuntimeError("Backend PvE yêu cầu Python 3.14; hãy dùng EXE đi kèm")
        if name in _MODULES:
            return _MODULES[name]
        filename = name + ".pyc"
        raw = (ROOT / filename).read_bytes()
        if (raw[:4] != importlib.util.MAGIC_NUMBER
                or hashlib.sha256(raw).hexdigest() != _MANIFEST["files"][filename]):
            raise RuntimeError(f"Backend PvE không khớp bản đã kiểm tra: {name}")
        code = marshal.loads(raw[16:])
        fullname = "pve_runtime._vendor_" + name
        module = types.ModuleType(fullname)
        module.__file__ = str(ROOT / filename)
        module.__package__ = "pve_runtime"

        def isolated_import(target, globals=None, locals=None, fromlist=(), level=0):
            if not level and target + ".pyc" in _MANIFEST["files"]:
                return load(target)
            return builtins.__import__(target, globals, locals, fromlist, level)

        module.__dict__["__builtins__"] = dict(vars(builtins), __import__=isolated_import)
        _MODULES[name] = module
        sys.modules[fullname] = module
        try:
            exec(code, module.__dict__)
        except BaseException:
            _MODULES.pop(name, None)
            sys.modules.pop(fullname, None)
            raise
        return module
