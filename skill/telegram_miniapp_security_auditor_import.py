from __future__ import annotations

import importlib.util
import sys
from pathlib import Path


def load_auditor():
    script = Path(__file__).resolve().parent / "telegram-miniapp-security-auditor" / "scripts" / "audit_tma.py"
    spec = importlib.util.spec_from_file_location("audit_tma", script)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"could not load {script}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module
